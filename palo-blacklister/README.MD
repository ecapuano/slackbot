# Palo Alto Blacklister for Slack

## Intro
A simple Slack integration that allows you to add entries to a dynamic blacklist used by a Palo Alto firewall.

VERY beta product and I am not a Python expert by any means, I just build things to make my life easier. If you see problems / areas to improve, feel free to contribute.


## Pre-reqs
First and foremost, this is meant to be used to modify the contents of an existing Dynamic Blocklist for a Palo Alto firewall...
Read up on that here: https://www.paloaltonetworks.com/documentation/61/pan-os/pan-os/policy/use-a-dynamic-block-list-in-policy.html

This integration assumes you are hosting the dynamic blacklist on another server that is accessible via SSH keypair.
Generate an SSH key and ensure you can SSH from the Slackbot server to the DBL (dynamic blacklist) server using the key.

Be sure to rename config.py.default to config.py and modify the settings for your environment. At this time, pretty much all fields are mandatory.

You may need to use requestbin to run some tests to find out what your Slack channel ID is. Or just enable debug on blockip.py and watch the console / log file.

Last but not least, be sure to add a crontab to start at boot...

`sudo crontab -e`

Add the following line:

`@reboot python /opt/slackbot/palo-blacklister/blockip.py`

## To-Dos
- Pep8 compliance
- General code cleanup
- Make a better readme.
- Option to not require a whitelisted channel_id (if you trust all of your Slack members)
- Ability to remove blacklist entries
- Ability to simply query the blacklist for an IP
- ??
