# logsta-services

This Python driven script will monitor a network for connections via TCPDump and Snort logs via auth.log.
It will covert logs into an Apache / Logstalgia accepted format and save them to a separate log file.
That file will then be redirected into Logstalgia and synced to display the logging in a visual format.
Leet right?
Enjoy!

Check the extras directory for the originals. (May need modified and may not be up to date)

Usage:

    1. mv example_config.py to config.py
    2. vim config.py, apply your configurations
    3. touch snort.log
    4. touch connections.log
    5. sudo ./logstafeed.py
    6. tail -F snort.log -F connections.log | logstalgia -x -g "SNORT,URI=^/SNORT/*,30,FF0000" -g "WAN-OUT,HOST=^192,30,FFFF00" -g "WAN-IN,URI=^/TCPDUMP/*,30,00FF00" --sync

Developed by: @h4cklife
