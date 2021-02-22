import os
import ssl
import smtplib
import logging
import datetime
import threading
from gcar import settings
from sleekxmpp import ClientXMPP
from sleekxmpp.xmlstream import cert
from past.builtins import basestring
from email.mime.text import MIMEText
from gcar.lib.throttler import TimeThrottler
from email.mime.multipart import MIMEMultipart
from gcar.lib.scheduled_responder import StoredMessage
from gcar.lib.scheduled_responder import ScheduledResponder

TALK_BRIDGE_DOMAIN = 'public.talk.google.com'

RESOURCE = 'gcar'

class ContextFilter(logging.Filter):
    """If context.log_id or context.bot_id is set, add them to log messages and tags.

    This separates sleekxmpp logs by autorespond and bot.
    """

    context = threading.local()

    @classmethod
    def filter(cls, record):
        for param in ('log_id', 'bot_id'):
            val = getattr(cls.context, param, None)
            if val is not None:
                record.msg = "[%s=%s] %s" % (param, val, record.msg)
                record.tags = getattr(record, 'tags', {})
                record.tags[param] = val

        return True

class GChatBot(ClientXMPP):
    """A long-running Bot that connects to Google Chat over ssl."""

    def __init__(self, email, token, log_id, **kwargs):
        """
        Args:
            email (unicode): the email to login as, including domain.
                Custom domains are supported.
            token (string): a `googletalk` scoped oauth2 access token
            log_id: if not None, will be prepended onto all logging messages triggered by this bot.
        """

        if '@' not in email:
            raise ValueError('email must be a full email.')
        
        self.email = email
        self.log_id = log_id
        self.bot_id = id(self)
        
        logger_name = __name__
        if self.log_id is not None:
            logger_name += str(self.log_id)

        self.logger = logging.getLogger(logger_name)

        self.logger.info("starting bot...")

        super(GChatBot, self).__init__(email + '/' + RESOURCE, token)

        self.use_ipv6 = False
        self.auto_reconnect = True
        
        self.logger.info("bot initialized. (thread id: %s)", id(self))

        self.add_event_handler('session_start', self.session_start)
        self.add_event_handler('ssl_invalid_cert', self.ssl_invalid_cert)

    # Since python doesn't have inheritable threadlocals, we need to set the context from one spot in each new thread.
    # These spots were found from http://sleekxmpp.com/_modules/sleekxmpp/xmlstream/xmlstream.html#XMLStream.process.
    # It doesn't include the scheduler thread, but that doesn't seem to log anything interesting.
    def _process(self, *args, **kwargs):
        ContextFilter.context.bot_id = self.bot_id
        if self.log_id:
            ContextFilter.context.log_id = self.log_id
        super(GChatBot, self)._process(*args, **kwargs)

    def _send_thread(self, *args, **kwargs):
        ContextFilter.context.bot_id = self.bot_id
        if self.log_id:
            ContextFilter.context.log_id = self.log_id
        super(GChatBot, self)._send_thread(*args, **kwargs)

    def _event_runner(self, *args, **kwargs):
        ContextFilter.context.bot_id = self.bot_id
        if self.log_id:
            ContextFilter.context.log_id = self.log_id
        super(GChatBot, self)._event_runner(*args, **kwargs)

    def connect(self):
        self.logger.info("connecting...")

        self.credentials['api_key'] = self.boundjid.bare
        self.credentials['access_token'] = self.password
        res = super(GChatBot, self).connect(('talk.google.com', 5222))
        
        self.logger.info("connected.")
        
        return res

    def session_start(self, event):
        self.logger.info("bot started.")
        # TODO try seeing if send_presence will trigger presence responses for use in autodetect
        self.send_presence()
        self.get_roster()

        # Most get_*/set_* methods from plugins use Iq stanzas, which
        # can generate IqError and IqTimeout exceptions. Example code:
        #
        # try:
        #     self.get_roster()
        # except IqError as err:
        #     logging.error('There was an error getting the roster')
        #     logging.error(err.iq['error']['condition'])
        #     self.disconnect()
        # except IqTimeout:
        #     logging.error('Server is taking too long to respond')
        #     self.disconnect()

    def ssl_invalid_cert(self, pem_cert):
        # Source: https://github.com/poezio/slixmpp/blob/master/examples/gtalk_custom_domain.py

        der_cert = ssl.PEM_cert_to_DER_cert(pem_cert)
        try:
            cert.verify('talk.google.com', der_cert)
            self.logger.info("found GTalk certificate.")
        except cert.CertificateError as err:
            self.logger.error(err.message)
            self.disconnect(send_close=False)

class AutoRespondBot(GChatBot):
    """A GChatBot that can respond to incoming messages with a set response.

    This works for all sender/receiver combinations ({gchat, hangouts} x {gchat, hangouts}).

    Hangouts messages are sent over a Google-internal xmpp bridge.
    They can mostly be treated normally, with two exceptions:

      * Hangouts senders have weird jids and don't reveal their email. This isn't
        a huge problem because we get their full name through the roster.
      * the body of Hangouts invites is never seen. This might be a bug? Or just something
        Google didn't want to build an extension for? Either way, this situation
        usually resolves itself, since we'll respond to the first message in the new conversation.

    There is a way to respond to chat invites, but it seems to be more trouble than it's worth.
    It involves listening for:
      * a roster subscription request from a Hangouts jid
      * later, a resource under that jid coming online
    """

    def __init__(self, email, response,
                send_email_notifications=False, notify_email=None,
                response_throttle=None, detect_unavailable=True,
                excluded_names=None, notification_overrides=None,
                disable_responses=False, enable_daily_digest=False,
                daily_digest_time=None, daily_digest_interval_hr=None):
        """
        Args:
            email (string): see GChatBot.
            token (string): see GChatBot.
            response (string): the message to respond with.
            send_email_notifications (bool): if true, send notification emails to notify_email.
                override with notification_overrides.
            notify_email (string): the email to send notifications to.
            response_throttle (Throttler): control how often the bot replies to the same jid.
                defaults to in-memory storage and 1 message / 5 mins limit.
            detect_unavailable (bool): when True, don't autorespond if another resource for the same account is
                available and not away.
            excluded_names (iterable of strings): contact names to not respond to, matched case-insensitive.
            notification_overrides ({'name': bool}): use to override send_email_notifications for contacts.
            disable_responses (bool): when True, never autorespond. Email notifications may still be sent.
        """

        logger_name = __name__

        self.logger = logging.getLogger(logger_name)

        self.logger.info("initializing...")
        
        if excluded_names is None:
            excluded_names = []

        if notification_overrides is None:
            notification_overrides = {}

        if response_throttle is None:
            response_throttle = TimeThrottler(datetime.timedelta(seconds=5))

        self.response = response
        self.notify_email = notify_email
        self.daily_digest_time = daily_digest_time
        self.disable_responses = disable_responses
        self.response_throttle = response_throttle
        self.detect_unavailable = detect_unavailable
        self.enable_daily_digest = enable_daily_digest
        self.notification_overrides = notification_overrides
        self.daily_digest_interval_hr = daily_digest_interval_hr
        self.send_email_notifications = send_email_notifications
        self.excluded_names = set(n.lower() for n in excluded_names)

        # self.disable_responses = not self.response

        if self.disable_responses:
            self.logger.info("automatic response has been disabled, incoming messages will NOT be replied to.")
        else:
            self.logger.info("automatic response has been enabled, incoming messages will be replied to.")

        if self.send_email_notifications or self.enable_daily_digest:
            try:
                self.logger.info("starting email server...")
                
                self.email_server = smtplib.SMTP(host=settings.EMAIL_HOST, port=settings.EMAIL_PORT)
                self.email_server.starttls()
                self.email_server.login(settings.EMAIL_HOST_USER, settings.EMAIL_HOST_PASSWORD)
                
                self.logger.info("email server started.")
            except Exception as ex:
                self.logger.error(str(ex))
                self.logger.error("could not start email server!")
                os._exit(1)
            finally:
                if self.send_email_notifications:
                    self.logger.info('email notifications configured as per message.')
                
                if self.enable_daily_digest:
                    self.logger.info('email notifications configured as daily digest.')

                    if not self.daily_digest_interval_hr and not self.daily_digest_time:
                        self.logger.error("daily_digest_interval_hr or daily_digest_time must be specified.")
                        raise Exception("specify daily_digest_interval_hr or daily_digest_time.")
                        
                    if self.daily_digest_time:
                        self.scheduled_responder = ScheduledResponder(email_server=self.email_server, time=self.daily_digest_time)
                        
                        # # for testing...
                        # current_date = datetime.datetime.strptime("%i:%i" %(datetime.datetime.now().hour, datetime.datetime.now().minute + 2), "%H:%M")
                        # self.scheduled_responder = ScheduledResponder(email_server=self.email_server, time=current_date.strftime("%I:%M %p"))
                    elif self.daily_digest_interval_hr:
                        self.scheduled_responder = ScheduledResponder(email_server=self.email_server, interval=self.daily_digest_interval_hr)
                        # self.scheduled_responder = ScheduledResponder(email_server=self.email_server, interval=0.0166666666666667) # 60000 ms (for testing)

                    self.scheduled_responder.start()

        self.other_active_resources = set()  # jids of other resources for our user

        super(AutoRespondBot, self).__init__(email, None, None)

        self.add_event_handler('message', self.message)
        self.add_event_handler('presence', self.presence)

        # uncomment this to respond to chat invites.
        # self.add_event_handler('roster_subscription_request',
        #                        self.roster_subscription_request)
        # self.add_event_handler('presence_available', self.detect_hangouts_jids)

        self.hangouts_jids_seen = set()

    def message(self, msg):
        """Respond to Hangouts/gchat normal messages."""

        jid = msg['from']
        msg_txt = msg.get('body')
        from_name = self.client_roster[jid]['name']
        
        self.logger.info("received message from (%s)[%s]. message:\n%s", from_name, jid, msg_txt)

        if msg['type'] in ('chat', 'normal') and self._should_send_to(msg['from']):
            did_reply = False

            if self.disable_responses:
                self.logger.info("not responding; responses are disabled.")
            elif self._is_excluded(jid):
                self.logger.info("not responding; %r is excluded.", jid)
            else:
                self.logger.info("responding to %s's message via message. response:\n%s", jid, self.response)
                msg.reply(self.response).send()
                did_reply = True
                self._update_response_throttler(jid, msg_txt)

            should_send_email = self.send_email_notifications
            notify_override = self.notification_overrides.get(from_name)
            if notify_override is not None:
                self.logger.info("received message from %s, overriding notification setting from %s to %s.",
                                    from_name, self.send_email_notifications, notify_override)
                should_send_email = notify_override

            # TODO store relevant information of this message and send them at a later time interval (every xx hours since bot started)
            # TODO store relevant information of this message and send them at a later specific time (at hh:mm:ss of every day)
            if self.enable_daily_digest:
                stored_message = StoredMessage(from_name, msg_txt, did_reply, self.response, self.notify_email)
                self.logger.debug('stored message for daily digest. %r', stored_message)
                self.scheduled_responder.store(stored_message)

            if should_send_email:
                self._send_email_notification(jid, msg_txt, did_reply)

    def presence(self, presence):
        other_jid = presence['from']
        if other_jid.bare == self.boundjid.bare:  # only compare the user+domain
            if other_jid == self.boundjid:
                # I have no idea why these happen.
                # It seems to happen for a single user exactly twice before stopping.
                self.logger.info('received loopback presence: %r,%r', self.boundjid, other_jid)
                return
            if other_jid.resource.startswith(RESOURCE):
                # There's probably something more to be done here, like ensuring only one autoresponder replies
                # (maybe the one with the highest resource?).
                # For now, they're not considered another resource, and multiple bots can respond.
                self.logger.error('more than one autoresponder is running? we are %s and they are %s',
                                    self.boundjid, other_jid)
                return

            if presence['type'] == 'available':
                self.other_active_resources.add(other_jid)
                self.logger.info('other resource came online: %s.', other_jid)
            elif presence['type'] in ('away', 'dnd', 'unavailable'):
                self.other_active_resources.discard(other_jid)
                self.logger.info('other resource %s now %s.', other_jid, presence['type'])

    def roster_subscription_request(self, presence):
        """Watch for Hangouts bridge chat invites and add them to `hangouts_jids_seen`."""

        from_jid = presence['from']

        if from_jid.domain == TALK_BRIDGE_DOMAIN:
            # Hangouts users get these goofy jids.
            # Replying to them doesn't seem to work, but replying to resources under it will.
            # So, we store the bare jid, with a weird name thing stripped out, then
            # wait for a resource to become active.
            if '--' in from_jid.user:
                waiting_jid = from_jid.bare.partition('--')[-1]
            else:
                waiting_jid = from_jid.bare

            self.logger.info("saw hangouts jid %s. message %r", from_jid, presence)
            self.hangouts_jids_seen.add(waiting_jid)

    def detect_hangouts_jids(self, presence):
        """Watch for Hangouts bridge jids coming online and respond to any in `hangouts_jids_seen`."""

        # TODO this should probably be removed, since it's diverged from the normal handler
        from_jid = presence['from']
        if from_jid.bare in self.hangouts_jids_seen and from_jid.resource:
            self.hangouts_jids_seen.remove(from_jid.bare)
            if self._should_send_to(from_jid):
                # Message type is important; omitting it will silently discard the message.
                self.logger.info("responding to %s via presence. message %r", from_jid, presence)
                self.send_message(mto=from_jid, mbody=self.response, mtype='chat')
                self._update_response_throttler(from_jid)

    def _update_response_throttler(self, jid, message=None):
        """Perform any bookkeeping needed after a response is sent.

        Args:
            jid: the jid that was responded to.
            message (string): the message received. None if unknown.
        """

        self.response_throttle.update(jid.bare)

    def _send_email_notification(self, from_jid, message, did_reply):
        """
        from_jid is a Jid.
        """

        # Building a decent representation of the sender is tricky.
        # We'll always at least have a jid.
        # Often they look like `...@public.talk.google.com/lcsw_hangouts_...` with no real meaning, though.
        from_identifier = from_jid.jid

        # Often we'll have the contact's name, which is better.
        from_nick = self.client_roster[from_jid.jid]['name']

        if from_nick and TALK_BRIDGE_DOMAIN not in from_jid.jid:
            # Rarely, we'll also have a valid email as the jid.
            from_identifier = "%s (%s)" %(from_nick, from_jid.bare)
        elif from_nick:
            from_identifier = from_nick

        body_paragraphs = ["you just received a message from %s." %from_identifier]

        if message is not None:
            body_paragraphs.append("The message was: \"%s\"." %message)
        else:
            body_paragraphs.append("Due to a bug on Google's end, we didn't receive a message body.")

        if did_reply:
            body_paragraphs.append("Bot replied with your autoresponse: \"%s\"." %self.response)
        else:
            body_paragraphs.append("Bot did not reply because you've disabled responses for this or all contacts.")

        subject = 'GCAR Notification'

        body_paragraphs.append(
            "If any of this is unexpected or strange, email abdalmoniemalhifnawy@gmail.com for support.")

        msg = MIMEMultipart()
        msg['from'] = settings.DEFAULT_FROM_EMAIL
        msg['to'] = self.notify_email
        msg['subject'] = subject
        msg.add_header('reply-to', settings.DEFAULT_REPLY_TO_EMAIL)
        msg.attach(MIMEText('\n\n'.join(body_paragraphs), 'plain'))
        
        try:
            self.email_server.send_message(msg)
            del msg
            self.logger.info("sent an email notification to %r", self.notify_email)
        except Exception as ex:
            self.logger.error("could not send an email notification. Error: %s", str(ex))

    def _is_excluded(self, jid):
        name = self.client_roster[jid.jid]['name']
        return bool(name and name.lower() in self.excluded_names)

    def _should_send_to(self, jid):
        """
        Return False if one of the following is true:
            * another resource is active
            * messages to the given jid are throttled
            * the message was from another autoresponder
        """

        if jid.resource.startswith(RESOURCE):
            self.logger.warning("will not send, %r is another autoresponder!", jid.full)
            return False

        if self.response_throttle.is_throttled(jid.bare):
            self.logger.info("will not send, bot is throttled!")
            return False

        if self.detect_unavailable:
            # Ideally we could check the status the other resources right now to make sure they're still active.
            # However, Google doesn't seem to respond to presence probes, and pings seem to always come back.
            if self.other_active_resources:
                self.logger.info('will not send, other resources are active: %s', self.other_active_resources)
                return False

        return True