
Metis
-----

A fun little project using twisted conch's library for the ssh protocol.
I wanted to explore ssh as an easy way to build authentication into other command line tools, since it's already part of every infrastructure toolkit.
Ultimately, its not that easy to do.

This has a server and a client which connect over ssh. the client can utilize the ssh-agent if one is running.

Todo:
- make the ssh-agent's socket available to the server, via a ssh channel (Agent Forwarding)
