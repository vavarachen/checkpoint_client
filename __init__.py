# -*- coding: utf-8 -*-
# A basic API wrapper to perform routine Check Point tasks
# Code tested with R80.20 release
#


import sys
import time
from socket import gethostname
from .api_client import APIClient
from pathlib import Path
from .utils import set_default_logger, add_logger_filehandler, get_config, is_ipaddress, is_uid, whoami

DEFAULT_CONFIG = Path.joinpath(Path(__file__).parent, "configs", "default.ini")
DEFAULT_LOG = Path.joinpath(Path(__file__).parent, "logs", "default.log")

DEFAULT_CONFIG_POSIX = DEFAULT_CONFIG.as_posix()
DEFAULT_LOG_POSIX = DEFAULT_LOG.as_posix()


# logger of last resort
def set_logger():
    logger = set_default_logger("CP_client", "DEBUG")
    add_logger_filehandler(logger, "DEBUG", DEFAULT_LOG_POSIX)


class CheckPointClient(APIClient):
    def __init__(self, config=None, logger=set_logger()):
        super().__init__()
        self.logger = logger
        self.configfile = config if config is not None else DEFAULT_CONFIG_POSIX
        try:
            if config is None:
                self.config = get_config(self.configfile, self.logger)
            else:
                self.config = get_config(config, self.logger)
        except Exception as err:
            print("Failed to read config (%s). Quitting!" % DEFAULT_CONFIG_POSIX)
            sys.exit(err)

        self.dryrun = self.config.getboolean('checkpoint', 'dryrun', fallback=True)
        self.default_color = self.config.get('checkpoint', 'color', fallback="deep pink")

        try:
            self.server = self.config.get('checkpoint', 'cp_server')
            self.fingerprint = self.config.get('checkpoint', 'fingerprint', fallback=None)
            if self.config.getboolean('checkpoint', 'verify_fingerprint', fallback=True):
                assert (self.fingerprint == self.get_server_fingerprint()), "Security Violation. Fingerprint Mismatch"
            else:
                self.logger.warning('Consider validating server fingerprint: %s') % self.get_server_fingerprint()

            # Only attempt to login if sid is invalid/expired
            self.sid = self.config.get('checkpoint', 'sid', fallback=None)
            resp = self.show_session()
            if (self.sid is None) or (not resp.success):
                self.__login__()
                self.__persist_sid__()

        except AssertionError as err:
            self.logger.critical("Fingerprint on file (%s) does not match server fingerprint (%s)"
                            % (self.fingerprint, self.get_server_fingerprint()))
            sys.exit(err)
        except Exception as err:
            self.logger.error("Failed to initialize Check Point Client. Quitting!")
            self.logger.debug("Exception Raised: %s" % err)
            sys.exit(err)
        #else:
        #    self.logger.debug("CheckPoint Client Successfully Initialized")

    def __persist_sid__(self):
        """
        Save state to reduce creation of new sids
        :return: None
        """
        self.config.set('checkpoint', 'sid', self.sid)
        with open(self.configfile, 'w') as configfile:
            self.config.write(configfile)

    def __repr__(self):
        return "checkpoint_client::CheckPointClient\n \tServer: %s, \tPort: %d, \tFingerprint: %s, " \
               "\tSID: %s, \tDebug File: %s" % (self.server, self.port, self.fingerprint, self.sid, self.debug_file)

    def __login__(self):
        """
        Read credentials from self.configuration file and authenticate.  Successful login will set 'X-chkp-sid' header.
        https://sc1.checkpoint.com/documents/R80/APIs/#gui-cli/login
        :return: None
        """
        try:
            resp = self.login(
                self.config.get('checkpoint', 'cp_server'),
                self.config.get('checkpoint', 'username'),
                self.config.get('checkpoint', 'password'),
                self.config.getboolean('checkpoint', 'resume_session', fallback=False),
                **{'domain': self.config.get('checkpoint', 'domain', fallback=""),
                       'session-comments': self.config.get('checkpoint', 'session-comments', fallback=""),
                       'session-description': self.config.get('checkpoint', 'session-description', fallback=""),
                       'session-name': "CPbot_%s_%s_%d" % (gethostname(), self.config.get('checkpoint', 'session-name',
                                                       fallback= Path(self.configfile).name), int(time.time())),
                       'session-timeout': self.config.getint('checkpoint', 'session-timeout', fallback=3600)}
            )
        except Exception as err:
            raise err
        else:
            if not resp.success:
                resp.data['_action'] = whoami()
                self.logger.error(resp.data)
                raise Exception("Authentication Failed. %s" % resp.data)

    def show_session(self, uid=None):
        """
        Show session information
        https://sc1.checkpoint.com/documents/latest/APIs/index.html#cli/show-session~v1.3
        :param sid: Unique session identifier
        :return: APIResponse object
        """
        if uid is not None:
            resp = self.api_call('show-session', {'uid': uid})
        else:
            resp = self.api_call('show-session')
        return resp

    def logout(self):
        """
        Terminate session
        :return: APIResponse object
        """
        resp = self.api_call('logout')
        if resp.success:
            resp.data['_action'] = whoami()
            self.logger.info(resp.data)
        else:
            # logout API error message is light on useful details.
            # Add session info for more context
            error = resp.data
            resp = self.show_session()
            resp.data['_action'] = whoami()
            resp.errors = [error]
            self.logger.error(resp.data)

    def show_group(self, obj_id, details_level='uid'):
        """
        Retrieve existing object using object name or uid.
        https://sc1.checkpoint.com/documents/R80/APIs/#gui-cli/show-group
        :param obj_id: name or uid
        :param details_level: valid values: uid, standard, full. Default: uid
        :return: APIResponse Object
        """
        if is_uid(obj_id):
            r_data = {'uid': obj_id, 'details-level': details_level}
        else:
            r_data = {'name': obj_id, 'details-level': details_level}

        resp = self.api_call('show-group', r_data)
        if resp.success:
            resp.data['_action'] = whoami()
            self.logger.debug(resp.data)
        else:
            self.logger.debug("Failed to retrieve %s" % obj_id)
            resp.data['_action'] = whoami()
            self.logger.error(resp.data)

        return resp

    def add_host(self, name, ipaddr, **kwargs):
        """
        Add host object
        https://sc1.checkpoint.com/documents/R80/APIs/#gui-cli/add-host
        :param name: Object name. Should be unique in domain
        :param ipaddr: IPv4 or IPv6 address
        :param kwargs: groups, tags, color, comments.  See API link for more.
        :return: APIResponse object
        """
        if is_ipaddress(ipaddr):
            r_data = {'name': name, 'ip-address': ipaddr}
            r_data.update(kwargs)

            _groups = kwargs['groups'] if 'groups' in kwargs.keys() else ""
            resp = self.api_call('add-host', r_data)
            if resp.success:
                resp.data['_action'] = whoami()
                self.logger.debug(resp.data)
            else:
                self.logger.debug("Failed to add %s to groups %s" % (ipaddr, _groups))
                resp.data['_action'] = whoami()
                self.logger.error(resp.data)

            return resp

    def delete_host(self, obj_id, ignore_warnings=False):
        """
        Delete host object
        https://sc1.checkpoint.com/documents/R80/APIs/#gui-cli/delete-host
        :param obj_id: name or uid
        :param warnings: apply changes ignore warnings.
        :return: APIResponse Object
        """
        return self.delete_object('host', obj_id, ignore_warnings)

    def delete_object(self, type, obj_id, ignore_warnings=False):
        """
        Delete object
        https://sc1.checkpoint.com/documents/R80/APIs/#gui-cli/delete-*
        :param obj_id: name or uid
        :param warnings: apply changes ignore warnings.
        :return: APIResponse Object
        """
        if is_uid(obj_id):
            r_data = {'uid': obj_id, 'ignore-warnings': ignore_warnings}
        else:
            r_data = {'name': obj_id, 'ignore-warnings': ignore_warnings}

        resp = self.api_call('delete-%s' % type, r_data)

        resp.data['_action'] = whoami()
        resp.data['type'] = type
        if is_uid(obj_id):
            resp.data['uid'] = obj_id
        else:
            resp.data['name'] = obj_id

        if resp.success:
            self.logger.debug(resp.data)
        else:
            self.logger.debug("Failed to delete %s" % obj_id)
            self.logger.error(resp.data)

        return resp

    def publish(self):
        """
        Make all changes performed by this session visible to all users
        https://sc1.checkpoint.com/documents/R80/APIs/#gui-cli/publish
        :return: APIResponse object
        """
        if self.dryrun:
            self.logger.debug("DRYRUN: Would have published changes")
        else:
            resp = self.api_call('publish')
            if resp.success:
                resp.data['_action'] = whoami()
                self.logger.info(resp.data)
            else:
                self.logger.error("Failed to publish changes.")
                resp.data['_action'] = whoami()
                self.logger.error(resp.data)

            return resp

    def install_policy(self, policy_package, targets, **kwargs):
        """
        Make all changes performed by this session visible to all users
        https://sc1.checkpoint.com/documents/R80/APIs/#gui-cli/publish
        :return: APIResponse object
        """
        kwargs['policy-package'] = policy_package
        kwargs['targets'] = targets
        if self.dryrun:
            # prepares the policy for the installation, but doesn't install it on an installation target.
            kwargs['prepare-only'] = True
        else:
            resp = self.api_call('install-policy', payload=kwargs)
            if resp.success:
                resp.data['_action'] = whoami()
                self.logger.info(resp.data)
            else:
                self.logger.error("Failed to install policy.")
                resp.data['_action'] = whoami()
                self.logger.error(resp.data)

            return resp

    def get_tag(self, obj_id, details_level="standard"):
        if is_uid(obj_id):
            r_data = {'uid': obj_id, 'details-level': details_level}
        else:
            r_data = {'name': obj_id, 'details-level': details_level}

        resp = self.api_call('show-tag', r_data)
        if resp.success:
            resp.data['_action'] = whoami()
            self.logger.debug(resp.data)
            return resp.data['name'] if is_uid(obj_id) else resp.data['uid']
        else:
            self.logger.debug("Failed to retrieve %s" % obj_id)
            resp.data['_action'] = whoami()
            self.logger.debug(resp.data)
            return ""
