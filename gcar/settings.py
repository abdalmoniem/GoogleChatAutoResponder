import os

def get_secret(filename):
    with open(os.path.join(SECRETS_DIR, filename)) as f:
        return f.read().strip()

def get_email_creds(filename):
    file_lines = []
    with open(os.path.join(SECRETS_DIR, filename)) as f:
        file_lines = f.readlines()
    
    email = file_lines[0].strip()
    password = file_lines[1].strip()

    return (email, password)

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SECRETS_DIR = os.path.join(BASE_DIR, 'secrets')

OAUTH_SCOPE = ' '.join(['https://www.googleapis.com/auth/googletalk', 'email'])

EMAIL_HOST = 'smtp.gmail.com'
EMAIL_PORT = 587
EMAIL_HOST_USER, EMAIL_HOST_PASSWORD = get_email_creds('email_creds.txt')
DEFAULT_FROM_EMAIL = 'Google Chat Auto Responder <%s>' % EMAIL_HOST_USER
DEFAULT_REPLY_TO_EMAIL = EMAIL_HOST_USER

LOGGING = {
    'version': 1,
    'disable_existing_loggers': False,
    'formatters': {
        'simple': {
            'format': '%(levelname)s: %(asctime)s - %(name)s (%(module)s:%(lineno)s): %(message)s'
        },
        'withfile': {
            'format': '%(levelname)s: %(asctime)s - %(name)s (%(module)s:%(lineno)s): %(message)s'
        },
    },
    'handlers': {
        'console_simple': {
            'class': 'logging.StreamHandler',
            'formatter': 'simple',
        },
        'console_verbose': {
            'class': 'logging.FileHandler',
            'filename': 'logs/logs.log',
            'formatter': 'withfile',
        },
    },
    'loggers': {
        'sleekxmpp': {
            # 'handlers': ['console_simple'],
            'handlers': ['console_simple', 'console_simple'],
            'level': 'INFO',
            'propagate': False,
        },
        'gcar': {
            # 'handlers': ['console_simple'],
            'handlers': ['console_simple', 'console_verbose'],
            'level': 'INFO',
            'propagate': False,
        },
    },
}