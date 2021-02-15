#--------------------------------------------------------------------------------#
#   File:      standalone_bot.py                                                 #
#   Author:    Abdelmoneim AlHifnawy, ISD-E-SW                                   #
#   Date:      Nov 11, 2020                                                      #
#--------------------------------------------------------------------------------#
#   COMPONENT: Google Chat Auto Responder                                        #
#   DESCRIPTION: Runs a bot that listens for incoming message on a specified     #
#                account and replies with a configured reply                     #
#   TARGET:    Python 3.7                                                        #
#--------------------------------------------------------------------------------#

"""
Google Chat Auto Responder Bot.

Use `auth` once to perform oauth and store a credentials file to the working directory.
Then, use `run` to start a bot from that credentials file.

Use SIGTERM to gracefully quiet or SIGQUIT to quit immediately.
Will exit and delete a credentials file upon revocation.

Usage:
    standalone_bot.py auth
    standalone_bot.py run --cfg <auto_response_file>
    standalone_bot.py run <email> [--ar <auto_response>]
    standalone_bot.py notify --cfg <auto_response_file>
    standalone_bot.py notify <email> [--ar <auto_response>]
    standalone_bot.py notify_digest --cfg <auto_response_file>
    standalone_bot.py notify_digest <email> [--di <digest_interval>] [--dt <digest_time>] [--ar <auto_response>]
    standalone_bot.py (-h | --help) 

Options:
    -h --help     Show this screen.
"""

import os
import json
import logging
import httplib2
import webbrowser
import logging.config
import oauth2client.file
from docopt import docopt
from gcar import settings
from builtins import input
from gcar.lib.bot import AutoRespondBot
from oauth2client.client import OAuth2WebServerFlow, AccessTokenRefreshError

EXIT_MESSAGE = 'bot killed!!!'

# configure logging and logging formatters
logging.config.dictConfig(settings.LOGGING)

def main():
    try:
        logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(asctime)s - %(name)s (%(module)s:%(lineno)s): %(message)s")

        arguments = docopt(__doc__)

        connected = False

        if arguments['auth']:
            perform_oauth()
            logging.info('authenticated successfully.')
            os._exit(0) # same as os._exit(os.EX_OK) which is not compatible with windows
        elif arguments['run']:
            if arguments['<auto_response_file>']:
                email, _, _, autoResponseMessage = read_autoResponse_file(arguments['<auto_response_file>'])

                if not autoResponseMessage:
                    logging.error("auto response message must be specified!")
                    os._exit(0) # same as os._exit(os.EX_OK) which is not compatible with windows

                bot = StandaloneBot(email, autoResponseMessage)
                
                connected = bot.connect()
                bot.process()
                # bot.process(block=True)
            else:
                if not arguments['<auto_response>']:
                    logging.error("auto response message must be specified!")
                    os._exit(0) # same as os._exit(os.EX_OK) which is not compatible with windows

                bot = StandaloneBot(arguments['<email>'], arguments['<auto_response>'])
                connected = bot.connect()
                bot.process()
                # bot.process(block=True)
        elif arguments['notify'] or arguments['notify_digest']:
            if arguments['<auto_response_file>']:
                email, digest_interval, digest_time, autoResponseMessage = read_autoResponse_file(arguments['<auto_response_file>'])
                
                bot = StandaloneBot(
                        email, autoResponseMessage,
                        send_email_notifications=(bool(arguments['notify'])),
                        notify_email=email,
                        disable_responses=(not bool(autoResponseMessage)),
                        enable_daily_digest=(bool(arguments['notify_digest'])),
                        daily_digest_time=digest_time,
                        daily_digest_interval_hr=digest_interval
                    )
                connected = bot.connect()
                bot.process()
                # bot.process(block=True)
            else:
                if not arguments['<auto_response>']:
                    logging.error("auto response message must be specified!")
                    os._exit(0) # same as os._exit(os.EX_OK) which is not compatible with windows
                
                if (not arguments['<digest_time>']) and (not arguments['<digest_interval>']):
                    logging.error("digest_time or digest_interval must be specified!")
                    os._exit(0) # same as os._exit(os.EX_OK) which is not compatible with windows

                digest_time = arguments['<digest_time>']
                digest_interval = int(arguments['<digest_interval>']) if arguments['<digest_interval>'] else None

                bot = StandaloneBot(
                        arguments['<email>'], arguments['<auto_response>'],
                        send_email_notifications=(bool(arguments['notify'])),
                        notify_email=arguments['<email>'],
                        disable_responses=(not bool(arguments['<auto_response>'])),
                        enable_daily_digest=(bool(arguments['notify_digest'])),
                        daily_digest_time=digest_time,
                        daily_digest_interval_hr=digest_interval
                    )
                connected = bot.connect()
                bot.process()
                # bot.process(block=True)
        while(connected): pass
        logging.info(EXIT_MESSAGE)
    except KeyboardInterrupt:
        logging.info(EXIT_MESSAGE)
        os._exit(0) # same as os._exit(os.EX_OK) which is not compatible with windows

def read_autoResponse_file(filename):
    config = json.load(open(filename, 'r'))

    email = config['email']
    digest_time = config['digest_time']
    digest_interval = int(config['digest_interval']) if config['digest_interval'] else None
    response = '\n'.join(config['response_lines']).strip() if config['response_lines'] else None

    return (email, digest_interval, digest_time, response)

def perform_oauth():
    """Provides a series of prompts for a user to follow to authenticate.
    Returns ``oauth2client.client.OAuth2Credentials`` when successful.
    In most cases, this should only be run once per machine to store
    credentials to disk, then never be needed again.

    If the user refuses to give access,
    ``oauth2client.client.FlowExchangeError`` is raised.
    """

    flow = OAuth2WebServerFlow(
        client_id='1070006574749-f9vjeakbk1vc2huc37v2ovv9lgclti77.apps.googleusercontent.com',
        client_secret='ngoE6A1JS8__X-C361DcKZDO',
        scope=settings.OAUTH_SCOPE,
        redirect_uri='urn:ietf:wg:oauth:2.0:oob',
    )

    auth_uri = flow.step1_get_authorize_url()
    print("Allow GoogleChatAutoResponder to view and send chat messages.")
    print("Visit the following url to do so:\n %s" % auth_uri)

    webbrowser.open(auth_uri)

    code = input("Follow the prompts, then paste the auth code here and hit enter: ")

    credentials = flow.step2_exchange(code)

    storage = StandaloneBot(credentials.id_token['email'], None, None, None, None, None).oauth_storage
    storage.put(credentials)

    return credentials

class StandaloneBot(AutoRespondBot):
    """An AutoResponseBot meant to be run from a shell.

    It's able to manage its own auth.
    """

    def __init__(self, *args, **kwargs):
        super(StandaloneBot, self).__init__(*args, **kwargs)

        self.reconnect_delay = 5

        self.add_event_handler('failed_auth', self.failed_auth)

    def failed_auth(self, _):
        """This event handler is triggered in two cases:

        * expired auth -> attempt to refresh and reconnect
        * revoked auth -> shutdown
        """

        credentials = self.get_oauth_credentials()

        try:
            self.logger.info("refreshing credentials...")
            credentials.refresh(httplib2.Http())
        except AccessTokenRefreshError as ex:
            self.logger.warning(str(ex))
            self.logger.warning("credentials revoked?")
            self.oauth_storage.delete()
            self.disconnect()
        else:
            self.logger.info("credentials refreshed.")
            self.password = credentials.access_token
            self.credentials['access_token'] = credentials.access_token
            self.oauth_storage.put(credentials)
            self.disconnect(reconnect=True)

    @property
    def oauth_filename(self):
        return "%s.oauth_credentials" % self.email

    @property
    def oauth_storage(self):
        return oauth2client.file.Storage(self.oauth_filename)

    def get_oauth_credentials(self):
        oauth_credentials = self.oauth_storage.get()
        if oauth_credentials is None:
            raise IOError("could not retrieve oauth credentials from %r. Have you run `auth`?" % self.oauth_filename)

        return oauth_credentials

    def connect(self):
        oauth_credentials = self.get_oauth_credentials()
        self.password = oauth_credentials.access_token

        return super(StandaloneBot, self).connect()

if __name__ == '__main__':
    main()