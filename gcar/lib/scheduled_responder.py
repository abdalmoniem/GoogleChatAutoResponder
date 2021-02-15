import time
import smtplib
import logging
from gcar import settings
from threading import Thread
from datetime import datetime
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

class StoredMessage:
    def __init__(self, from_nick, msg_txt, did_reply, response, notify_email):
        self.stamp = datetime.now().strftime('%a, %d-%b-%Y %I:%M:%S %p')
        self.from_nick = from_nick
        self.msg_txt = msg_txt
        self.did_reply = did_reply
        self.response = response
        self.notify_email = notify_email

    def __str__(self):
        return (self.stamp, self.from_nick,
                self.msg_txt, self.did_reply,
                self.response, self.notify_email)

    def __repr__(self):
        return '%s(%s, %s, %s, %s, %s, %s)' %('.'.join([type(self).__module__, type(self).__name__]), 
                                                self.stamp, self.from_nick,
                                                self.msg_txt, self.did_reply,
                                                self.response, self.notify_email)


class ScheduledResponder(Thread):
    def __init__(self, interval=None, time=None, email_server=None):
        self.logger = logging.getLogger(__name__)
        self.logger.info('starting scheduled responder...')

        Thread.__init__(self)

        self.time = None
        self.interval_ms = None

        if time:
            self.time = datetime.strptime(time, '%I:%M %p')
            self.logger.info('scheduled digest time: %s', self.time.strftime('%I:%M %p'))
        elif interval:
            self.interval_ms = interval * 60 * 60 * 1000
            self.logger.info('scheduled digest interval: %f hrs (%f ms)', interval, self.interval_ms)

        self.stored_messages = []

        if not email_server:
            raise Exception('Email Server cannot be None.')
        
        self.email_server = email_server

        self.logger.info('scheduled responder started')

    def run(self):
        if self.time:
            self.logger.info('running scheduler with time.')
            while(True):
                if len(self.stored_messages) > 0:  
                    current_time = datetime.now()
                    if (current_time.hour == self.time.hour) and (current_time.minute == self.time.minute):
                        self._prepare_email_body()
        elif self.interval_ms:
            self.logger.info('running scheduler with interval.')

            start_time = int(round(time.time() * 1000))
            while(True):
                if len(self.stored_messages) > 0:                
                    current_time = int(round(time.time() * 1000))
                    time_delta = current_time - start_time

                    if time_delta > self.interval_ms:
                        self._prepare_email_body()
                        start_time = int(round(time.time() * 1000))

    def store(self, item):
        self.stored_messages.append(item)        

    def _prepare_email_body(self):
        email_message_body = ''
        item_count = 1
        for item in self.stored_messages:
            # stamp = list(item.keys())[0]
            # from_nick = list(list(list(item.values()))[0].keys())[0]
            # msg_txt = list(list(list(item.values()))[0].values())[0][0]
            # did_reply = list(list(list(item.values()))[0].values())[0][1]
            # response = list(list(list(item.values()))[0].values())[0][2]
            # notify_email = list(list(list(item.values()))[0].values())[0][3]
            
            email_message_body += 'Message #%i:\n' %item_count
            email_message_body += 'Timestamp: %s\n' %item.stamp
            email_message_body += 'From: %s\n' %item.from_nick
            email_message_body += 'Received Message: %s\n' %item.msg_txt
            
            if item.did_reply: 
                email_message_body += 'Action: replied\n'
                email_message_body += 'Bot replied with your autoresponse:\n%s.\n' %item.response
            else:
                email_message_body += 'Action: did not reply\n'
                email_message_body += 'Bot did not reply because you\'ve disabled responses for this or all contacts.\n'
            
            email_message_body += '\n\n'

            item_count += 1
            
        self._send_email_notification(email_message_body, item.notify_email)
        self.stored_messages.clear()

    def _send_email_notification(self, email_message_body, notify_email):
        body_paragraphs = ['Your Daily Digest:\n\n']

        body_paragraphs.append(email_message_body)
        
        body_paragraphs.append('If any of this is unexpected or strange, email abdalmoniemalhifnawy@gmail.com for support.')

        msg = MIMEMultipart()
        msg['from'] = settings.DEFAULT_FROM_EMAIL
        msg['to'] = notify_email
        msg['subject'] = 'GCAR Daily DIGEST'
        msg.add_header('reply-to', settings.DEFAULT_REPLY_TO_EMAIL)
        msg.attach(MIMEText(''.join(body_paragraphs), 'plain'))
        
        try:
            self.email_server.send_message(msg)
            del msg
            self.logger.info('sent an email notification to %r', notify_email)
        except Exception as ex:
            self.logger.error('could not send an email notification. Error: %s', str(ex))