from app.celery import app as celery_app
from celery import signals
import logging

__all__ = ('celery_app', )

@signals.setup_logging.connect
def on_celery_setup_logging(**kwargs):
    config = {
        'version': 1,
        'disable_existing_loggers': False,
        'formatters': {
            'verbose': {
                'format': '{levelname} {asctime} {module} {process:d} {thread:d} {message}',
                'style': '{',
            },
            'simple': {
                'format': '{levelname} {asctime} {message}',
                'style': '{',
            },
        },
        'handlers': {
            'file': {
                'level': 'INFO',
                'class': 'logging.FileHandler',
                'filename': 'celery.log',
                'formatter': 'simple'
            },
            'console':{
                'level': 'INFO',
                'class': 'logging.StreamHandler',
            },
            'celery': {
                'level': 'DEBUG',
                'class': 'logging.FileHandler',
                'filename': 'celery.log',
                'formatter': 'simple',
            },
        },
        'loggers': {
            'celery': {
                'handlers': ['console', 'celery'],
                'level': 'INFO',
                'propagate': False
            },
        },
        'root': {
            'handlers': ['console'],
            'level': 'DEBUG'
        },
    }
    logging.config.dictConfig(config)