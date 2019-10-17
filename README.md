# logsta-services

This Python driven script will monitor a network for connections via Netstat and Snort logs via auth.log.
It will covert logs into an Apache / Logstalgia accepted format and save them to a separate log file.
That file will then be redirected into Logstalgia and synced to display the logging in a visual format.
Leet right?
Enjoy!

This script may run better split into 2 scripts, but I wanted them combined, so FTW. Here is the combined version.

Check the extras directory for the originals. (May need modified and may not be up to date)

Usage:

    1. python3 logstafeed.py
    2. tail -F snort.log | logstalgia --sync

Developed by: @h4cklife