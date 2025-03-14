import logging
import re
import socket

SECRETS = [r"password", r"secret", r"token"]
MASKED = True
FILENAME = "var.log"
TCP = False


class SensitiveFilter(logging.Filter):
    def __init__(self, filter_msg):
        super(SensitiveFilter, self).__init__()

        self.filter_msg = filter_msg

    def filter(self, record):
        """
        :param record: LogRecord Object
        :return True to accept record, False to drop record
        """
        for secret in SECRETS:
            record.msg = re.sub(rf"{secret}=(.*)", rf"{secret}=********", record.msg)
        return True


DATE_FMT = "%Y-%m-%d %H:%M:%S"

dict_config = {
    "version": 1,
    "disable_existing_loggers": False,  # default True
    "filters": {
        "mask_filter": {
            "()": SensitiveFilter,
            "filter_msg": " ***filtered***",
        },
    },
    "formatters": {
        "single-line": {
            "datefmt": DATE_FMT,
            "format": "%(asctime)s %(levelname)-5s %(processName)s %(name)s -: %(message)s",
        },
        "multi-process": {
            "datefmt": DATE_FMT,
            "format": "%(asctime)s|%(levelname)-8s|%(processName)s|%(name)s: %(message)s",
        },
        "multi-thread": {
            "datefmt": DATE_FMT,
            "format": "%(asctime)s|%(levelname)-8s|%(threadName)s|%(name)s: %(message)s",
        },
        "verbose": {
            "datefmt": DATE_FMT,
            "format": "%(asctime)s|%(levelname)-8s:%(processName)s:%(threadName)s|%(name)s:%(module)s:%(funcName)s:%(lineno)d"
            "> %(message)s",
        },
        "multiline": {
            "datefmt": DATE_FMT,
            "format": "Time: %(asctime)s\nLevel: |%(levelname)-8s\nProcess: %(process)d\nThread: %(threadName)s\nLogger"
            ": %(name)s\nPath: %(module)s:%(lineno)d\nFunction :%(funcName)s\nMessage: %(message)s\n",
        },
        "clientf": {
            "datefmt": DATE_FMT,
            "format": "%(asctime)s %(levelname)-5s %(processName)s %(name)s %(brain)s -: %(message)s",
        },
    },
    "handlers": {
        "console": {
            "class": "logging.StreamHandler",
            "formatter": "single-line",
            "filters": ["mask_filter"] if MASKED is True else [],
            "stream": "ext://sys.stdout",
        },
        "file": {
            "class": "logging.handlers.RotatingFileHandler",
            "formatter": "verbose",
            "filename": FILENAME,
            "filters": ["mask_filter"] if MASKED is True else [],
            "mode": "a",
            "maxBytes": 10000000,
            "backupCount": 5,
            "encoding": "utf-8",
        },
        "clienth": {
            "class": "logging.StreamHandler",
            "formatter": "clientf",
            "filters": ["mask_filter"] if MASKED is True else [],
            "stream": "ext://sys.stdout",
        },
        "null_handler": {
            "level": "DEBUG",
            "class": "logging.NullHandler",
        },
        # "smtp": {
        #     "class": "logging.handlers.SMTPHandler",
        #     "formatter": "multiline",
        #     "filters": ["mask_filter"] if MASKED is True else [],
        #     "mailhost": ["127.0.0.1", 60025],
        #     "fromaddr": "sender@example.com",
        #     "toaddrs": ["recipient@example.com"],
        #     "subject": "Something went wrong",
        #     "credentials": None,
        #     "secure": None,
        #     "timeout": 1.0,
        # },
        # "syslog": {
        #     "class": "logging.handlers.SysLogHandler",
        #     "formatter": "single-line",
        #     "filters": ["mask_filter"] if MASKED is True else [],
        #     "address": ("192.168.54.103", 514),
        #     "socktype": socket.SOCK_DGRAM if not TCP else socket.SOCK_STREAM,
        # },
    },
    "loggers": {
        "": {  # this is root logger
            "level": "",
            "handlers": ["null_handler"],
        },
        "urllib3": {
            "level": "WARNING",
            "handlers": ["console"],
        },
        "VAR": {
            "level": "",
            "handlers": ["console", "file"],
        },
        "VAR_Client": {
            "level": "",
            "handlers": ["file", "clienth"],
        },
        # "syslog": {
        #     "level": "INFO",
        #     "handlers": ["syslog"],
        # },
        # "paramiko": {"level": "WARNING", "handlers": ["file"]},
    },
}
