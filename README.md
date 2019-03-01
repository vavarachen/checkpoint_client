# checkpoint_client
A python client to interact with CheckPoint R80 API (https://sc1.checkpoint.com/documents/R80/APIs/#ws).

# Installation
```bash
pip install checkpoint-client
```

# Features
1. Perform basic functionality such as add/delete objects, get tags, show objects in group, publish and install policy.
2. Authentication session (sid) can persist using configuration file.  If session is invalid, automatically re-authenticate and update sid.
3. Management server fingerprint verification.

# Disclaimers
1. CheckPoint R80 API does not allow adding/deleting multiple host objects to a group in one call.  Each host object must be created and then added/deleted to the group.  This results in very slow (serial) execution.
2. In our testing, we have noticed some instability with very large set (10k+) of changes.

# Example
Sample configuration file
```ini
[checkpoint]
username = myusername
# API does not support cert based authentication
password = mypassword
domain = DMZ

# Some useful fileds to make CP session more descriptive
session-name = inet_blacklist
session-comments = API automation example
session-description = Automated DMZ blacklisting of known malicious IPs (from TIP).
cp_server = 10.10.100.32

# Exit if fingerprint verification fails
fingerprint = 82C9C0B60850901BBDF5653D794ADF8E8AAEA1B7
verify_fingerprint = True

# No changes made if set to True
dryrun = False

# Automatically populated if authentication successful
sid = 

[dmz_blacklist]
color = red
group = GRP-DMZ_BAD_IP_FROM_TIP
target = LAB_DMZ_CLUSTER
```

A simple script to add host objects to an existing group object, publish changes and finally, install the policy.
```python
from checkpoint_client import CheckPointClient
from checkpoint_client.utils import set_default_logger, add_logger_streamhandler

# Instantiate a client
logger = set_default_logger("inet_blacklist_mgr", "DEBUG")
add_logger_streamhandler(logger, "INFO")
cpc = CheckPointClient('configs/example.ini', logger)

bad_IPs = ['1.2.3.4', '5.6.7.8', '9.0.11.12', '13.14.15.16']

color = config.get('dmz_blacklist', 'color', fallback=cpc.default_color),
group = config.get('dmz_blacklist', 'group', fallback="MY_DEFAULT_GROUP")
target = config.get('dmz_blacklist', 'target', fallback="DMZ_CLUSTER")

success_count = 0
fail_count = 0
for bad_ip in bad_IPs:
    resp = cpc.add_host(
        name=bad_ip,
        ipaddr=bad_ip,
        tags="bad_ips_from_tip",
        comments="Import example using API wrapper",
        color=color,
        groups=group)
    if resp.success:
        success_count += 1
    else:
        fail_count += 1

logger.info({'message': {'total': len(bad_IPs), 'success': success_count, 'fail': fail_count})

# Publish changes
resp = cpc.publish()
if resp.success:
    logger.info({'message': "Policy publication successful"})
else:
    logger.error('message': "Policy publication failed.")
    
# Install policy
# https://sc1.checkpoint.com/documents/R80/APIs/?#gui-cli/install-policy
params = {'access': True, 'threat-prevention': False, 'install-on-all-cluster-members-or-fail': True} 

resp = cpc.install_policy(group, target, **params)
if resp.success:
    logger.info({'message': "Policy installation successful"})
else:
    logger.error('message': "Policy installation failed.")
    
cpc.logout()
```
