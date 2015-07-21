import urllib.request
import sys
import getopt

proxylist = ""


def getProxy():
    return proxylist[0]

def delProxyFromList(proxy):
    proxylist.remove(proxy)
    return getProxyListSize()

def getProxyListSize():
    return len(proxylist)

def printUsage():
    print("Usage: goodproxy.py -f <proxyfile> -u <url> -t <timeout>")
     
    
def testproxy(url, _timeout):


    try:
                
        ip  = getProxy()
                
        # CONFIGURE URLLIB TO USE PROXY     
        proxy   = urllib.request.ProxyHandler({'http': ip })
        opener  = urllib.request.build_opener(proxy)
        urllib.request.install_opener(opener)
                      
        request = urllib.request.Request(url, headers = { 'User-Agent' : 'Proxy Tester' })

        # ATTEMPT TO FETCH URL
        result = urllib.request.urlopen(request, timeout=float(_timeout)).read().decode("utf-8")
         
        if "<html" in result:       
            print(result)
            sys.exit(1)
                        
        # IF ALL WENT WELL THEN SAVE THIS PROXY 
        with open("result.txt",'a') as outfile:
            print(ip,file=outfile)

        # THIS PROXY WAS TESTED SUCCESSFULLY SO REMOVE FROM LIST
        print("Proxy List Now: {0}".format(delProxyFromList(ip)))
    
    except urllib.request.URLError as e:
    # THIS PROXY WAS TESTED AND FAILED SO REMOVE FROM LIST
        print(e)
        print("----- Bad Proxy: " + ip + " Proxy List Now: {0}".format(delProxyFromList(ip)))
        
        
    except urllib.request.HTTPError as e:
        print(e)
        # THIS PROXY WAS TESTED AND FAILED SO REMOVE FROM LIST
        print("----- Bad Proxy: " + ip + " Proxy List Now: {0}".format(delProxyFromList(ip)))
        
    except:
        # THIS PROXY WAS TESTED AND FAILED SO REMOVE FROM LIST
        print(sys.exc_info()[0])
        print("----- Bad Proxy: " + ip + " Proxy List Now: {0}".format(delProxyFromList(ip)))
        


def main(argv):    
    
    filename    = ""
    url         = ""
    timeout     = None
    
    try:
        
        # USE GETOPS FOR EASIER PARAMETER PROCESSING
        opts, args = getopt.getopt(argv, "f:u:t:",["file=", "url=", "timeout="])
    
    except getopt.GetoptError:
        
        printUsage()
        sys.exit(2)
        
    
    # CHECK FOR MISSING PARAMETERS
    # THE 'OPTS' OBJECT CONSISTS OF A LIST OF TUPLES LIKE (PARAM,VAL)
    # LIST COMPREHENSION COLLECTS FIRST ELEMENTS FROM EACH TUPLE INTO A NEW LIST 
    # THEN TESTS THE NEW LIST FOR THE REQUIRED PARAMS 
    if not any(f in [opt[0] for opt in opts] for f in ['-f','--file']):
        printUsage()
        print("Error: -f parameter missing")
        sys.exit(2)
         
    if not any(u in [opt[0] for opt in opts] for u in ['-u','--url']):
        printUsage()
        print("Error: -u parameter missing")
        sys.exit(2)

    if not any(t in [opt[0] for opt in opts] for t in ['-t','--timeout']):
        printUsage()
        print("Error: -t parameter missing")
        sys.exit(2)
        
    
    # CONFIGURE SETTINGS BASED ON THE PASSED IN PARAMETERS
    for opt, arg in opts:
        
        if opt in ('-f', '--file'):
            
            print("Using proxies in: " + arg)
            filename = arg
            
        elif opt in ('-u', '--url'):
            
            print("Using URL: " + arg)
            url = arg
            
        elif opt in ('-t', '--timeout'):
            
            print("Timeout: {0}s".format(arg))
            timeout = arg
        
        
    # LOAD LIST OR PROXIES FROM THE PROXY FILE
    with open(filename) as f:
        global proxylist
        proxylist = [line.strip() for line in f]

    if not proxylist:
        print("No proxies found for testing.")
        sys.exit(1)
    else:
        print("Testing {0} proxies.".format(getProxyListSize()))
        
        
    # LOOP EVERY PROXY
    while getProxyListSize() > 0:
        testproxy(url, timeout)


if __name__ == "__main__":
    main(sys.argv[1:])
