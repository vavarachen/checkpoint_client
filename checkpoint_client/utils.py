# -*- coding: utf-8 -*-
import logging
import configparser
import sys
import pathlib
import platform
import ipaddress
import re

# e7f23e3c-c755-4dc9-99e5-363d7b541856
UID_RE = re.compile("[a-z0-9]{8}-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{12}")

def set_default_logger(logger_name=None, logger_level=logging.DEBUG, propagate=False):
    if logger_name is None:
        logger = logging.getLogger(__name__)
    else:
        logger = logging.getLogger(logger_name)
    logger.setLevel(logger_level)
    logger.propagate = propagate
    return logger


def add_logger_streamhandler(logger=set_default_logger(), logger_level=logging.INFO, format=None):
    """
    :param logger_name: Typically, name of calling module
    :param logger_level: Log verbosity level
    :return: logging.Logger
    """
    if format is None:
        _format = logging.Formatter(u"%(asctime)s - %(name)s - %(levelname)s - %(message)s")
    else:
        _format = logging.Formatter(format)
    try:
        handler = logging.StreamHandler()
        handler.setLevel(logger_level)
    except Exception as e:
        print("Failed to set logger (%s).  Falling back to defaults." % e)
        handler = logging.StreamHandler()
        handler.setLevel(logging.DEBUG)
    finally:
        handler.setFormatter(_format)
        logger.addHandler(handler)
        return logger


def add_logger_filehandler(logger=set_default_logger(), logger_level=logging.INFO, filename='default.log', format=None):
    """
    add a file log handler to an existing logger
    :param logger: Typically, name of calling module
    :param logger_level: Log verbosity level
    :param format: Log output format
    :return: logging.Logger
    """
    if format is None:
        _format = logging.Formatter(u"%(asctime)s - %(name)s - %(levelname)s - %(message)s")
    else:
        _format = logging.Formatter(format)
    try:
        fh = logging.FileHandler(filename)
        fh.setLevel(logger_level)
        fh.setFormatter(_format)
        logger.addHandler(fh)
    except Exception as e:
        logger.error("Failed to set %s as log file handler. Error: %s" % (filename, e))
    finally:
        return logger


def add_logger_splunkhandler(logger=set_default_logger(), **kwargs):
    """
    Handler for writing logs to Splunk index.
    https://github.com/vavarachen/splunk_hec_handler
    :param logger: logging instance
    :param kwargs: Splunk configuration options
    :return: logger with Splunk Handler attached
    """
    try:
        from splunk_hec_handler import SplunkHecHandler
        import urllib3
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    except Exception as err:
        logger.warning("Failed to add Splunk log handler. Error: %s" % err)
        return logger
    else:
        try:
            host = kwargs.pop('host')
            token = kwargs.pop('token')
            level = kwargs.pop('level') if 'level' in kwargs.keys() else 'INFO'
            sh = SplunkHecHandler(host, token, **kwargs)
        except Exception as err:
            logger.warning("Failed to add Splunk log handler.  Error: %s" % err)
            raise err
        else:
            sh.setLevel(level)
            logger.addHandler(sh)
    return logger


def get_config(conf_file=None, logger=set_default_logger()):
    """
    :param conf_file: configparser compliant configuration file
    :param logger: Log handler, typically from calling module
    :return: configparser.ConfigParser
    """
    os_type = platform.system()
    if os_type == "Windows":
        if conf_file is None:
            conf_file = pathlib.PureWindowsPath('default.conf')
        else:
            conf_file = pathlib.PureWindowsPath(conf_file)
    else:
        if conf_file is None:
            conf_file = pathlib.PurePosixPath('default.conf')
        else:
            conf_file = pathlib.PurePosixPath(conf_file)

    config = configparser.ConfigParser(comment_prefixes='/', allow_no_value=True)
    try:
        config.read_file(open(conf_file.as_posix()))
    except Exception as e:
        logger.warning("Failed to parse configuration file %s" % conf_file.name)
        logger.error("Except raised: %s" % e)
    finally:
        return config


def is_ipaddress(ip_str):
    try:
        ipaddress.ip_network(str(ip_str))
    except ValueError as err:
        return False
    else:
        return True


def is_uid(obj_id):
    try:
       id_str = str(obj_id).lower()
    except Exception:
        return False
    else:
        return UID_RE.match(id_str)


# https://www.oreilly.com/library/view/python-cookbook/0596001673/ch14s08.html
def whoami():
    return sys._getframe(1).f_code.co_name


def callersname():
    return sys._getframe(2).f_code.co_name
