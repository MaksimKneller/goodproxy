## GoodProxy is a multithreaded proxy checker with anonymity analysis. 

Given a file containing a list of proxies, in a form of ip:port, attempts
to connect through each proxy to a local web server. If successful, the web
server collects the headers coming out of the proxy and returns them to the
calling thread for anonymity analysis.

Anonymity levels are defined as follows:

    Level 1: Elite Proxy - hides source IP and that it is a proxy
    Level 2: Anonymous Proxy - hides source IP but labels itself as a proxy
    Level 3: Transparent Proxy - both source IP and proxy details are visible
    
Because this program spins off a local web server to simulate a recipient of
proxied requests - the port it runs on needs to be port-forwarded on
your router.

##Usage:

    goodproxy.py [-h] -wanip WANIP [-port PORT] [-file FILE] [-timeout TIMEOUT] [-threads THREADS]
                
Parameters:

    -wanip   -- your external IP (as at whatismyip.org)
    -port    -- for the local web server (default 80)
    -file    -- filename with a list of proxies per line (default proxies.txt)
    -timeout -- time in seconds for connecting to a proxy (default 1.0)
    -threads -- number of threads to boost performance (default 8)
    
    
##Functions:

    test_proxy           -- does the actual connecting through a proxy
    main                 -- creates daemon threads, writes results to a file
    
##Output:

Creates a result.csv with a comma-delimited list of proxies and results like the anonymity level, time to connect and headers sent out by the proxy.

