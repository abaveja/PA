import time, random, threading, json,datetime, socket, sys

#region data to load
broker_ip = ""
broker_port = ""
webpath = []
useragents = []
ports = []
usershosts = []
ipssignatures = []
uris = []
#endregion

def ReadFile(fpath):
    #reading the config files and returing their content
    data = []
    with open(fpath, "r") as d:
        for line in d:
            data.append(line)
    return data

def LoadConfig():
    global broker_port, broker_ip, webpath, useragents, ports, usershosts, ipssignatures, uris
    #loading broker port and ip
    with open("config.json") as conf:
        config = json.load(conf)
        broker_ip = config["broker_ip"]
        broker_port = config["broker_port"]
        if len(broker_ip) < 1 or len(broker_port) < 1:
            print("Please add your Broker VM IP and Port in the conf file")
            sys.exit()
        else:
            print("Will send logs to Broker VM at " + broker_ip + ":" + broker_port)
    #loading bad paths for directory traversal:
    webpath = ReadFile("data/webpath.txt")
    #loading a bunch of useragents:
    useragents = ReadFile("data/useragents.txt")
    #loading a bunch of ports and services:
    ports = ReadFile("data/ports.txt")
    #loading a bunch of users and hosts:
    usershosts = ReadFile("data/usershostsips.txt")
    #loading a bunch of ips signatues:
    ipssignatures = ReadFile("data/ips.txt")
    #loading a bunch of UIRs :
    uris = ReadFile("data/URIs.txt")

def SendData(datatosend):
    # Create a UDP socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    try:
        # Send the syslog message to the specified IP address and port
        sock.sendto(datatosend.encode(), (broker_ip, int(broker_port)))
        print("Syslog message sent successfully.")
    except Exception as e:
        print("Error sending syslog message:", e)
    finally:
        # Close the socket
        sock.close()

def ApacheTimestamp():
    # Get the current time
    current_time = datetime.datetime.utcnow()

    # Get the UTC offset
    utc_offset = current_time.utcoffset()

    # Check if the UTC offset is not None
    if utc_offset is not None:
        # Calculate the UTC offset in minutes
        utc_offset_minutes = utc_offset.total_seconds() // 60
        formatted_offset = "{:02}{:02}".format(int(utc_offset_minutes // 60), int(utc_offset_minutes % 60))
    else:
        # Default to UTC (no offset)
        formatted_offset = "+0000"

    # Format the timestamp
    formatted_time = current_time.strftime("[%d/%b/%Y:%H:%M:%S {}]").format(formatted_offset)

    return formatted_time

def GeneratePublicIp():
    # Define ranges for the first octet of public IP addresses
    first_octet_ranges = [(1, 126), (128, 191), (192, 223)]

    # Randomly select a range for the first octet
    first_octet_range = random.choice(first_octet_ranges)
    first_octet = random.randint(first_octet_range[0], first_octet_range[1])

    # Generate the rest of the octets
    second_octet = random.randint(0, 255)
    third_octet = random.randint(0, 255)
    fourth_octet = random.randint(0, 255)

    # Combine octets into an IP address string
    ip_address = f"{first_octet}.{second_octet}.{third_octet}.{fourth_octet}"
    return ip_address

def CheckPointFWScan():
    # This code simulates a scan, where we pick a segment in /24 range and a TCP port and try to access every IP in that range
    while True:
        try:
            CEF = "CEF:0|Check Point|VPN-1 & FireWall-1|Check Point|Log|$app|informational|act=$act spt=$spt dpt=$dpt dst=$dst src=$src app=$app suser=$suser shost=$shost proto=$proto"
            actions = ["accept","accept","drop"]
            act = actions[random.randint(0,len(actions)-1)]
            source = usershosts[random.randint(0,len(usershosts)-1)].split(",")
            suser = source[1]
            shost = source[2]
            src = source[3].replace("\n","")
            spt = str(random.randint(49152,65535))
            dstservice = ports[random.randint(0,len(ports)-1)].split(",")
            while dstservice[2].replace("\n","") == "UDP":
                dstservice = ports[random.randint(0,len(ports)-1)].split(",")
            dpt = dstservice[0]
            app = dstservice[1]
            proto = dstservice[2].replace("\n","")
            ip = "172.16." + str(random.randint(1,250))
            for i in range(256):
                dst = ip + "." + str(i)
                Log = CEF.replace("$dst", dst).replace("$proto", proto).replace("$app", app).replace("$act",act).replace("$src",src).replace("$spt",spt).replace("$dpt",dpt).replace("$suser",suser).replace("$shost",shost)
                print(Log)
                SendData(Log)
                time.sleep(random.randint(1,2))
        except Exception as e:
            print(e)
        #going to sleep for about an hour
        time.sleep(random.randint(3200,4000))

def CheckPointFW():
    while True:
        try:
            CEF = "CEF:0|Check Point|VPN-1 & FireWall-1|Check Point|Log|$app|informational|act=$act spt=$spt dpt=$dpt dst=$dst src=$src app=$app suser=$suser shost=$shost proto=$proto"
            actions = ["accept","accept","drop"]
            act = actions[random.randint(0,len(actions)-1)]
            source = usershosts[random.randint(0,len(usershosts)-1)].split(",")
            suser = source[1]
            shost = source[2]
            src = source[3].replace("\n","")
            dstservice = ports[random.randint(0,len(ports)-1)].split(",")
            dpt = dstservice[0]
            app = dstservice[1]
            proto = dstservice[2].replace("\n","")
            spt = str(random.randint(49152,65535))
            if dpt in ["80","443"] and ("1" in str(datetime.datetime.now().minute) or "3" in str(datetime.datetime.now().minute) or "5" in str(datetime.datetime.now().minute) or "9" in str(datetime.datetime.now().minute)) and ("2" in spt or "8" in spt) and "a" in suser and ("7" in src or "8" in src):
                dst = "172.16.2.2"
            elif dpt in ["80","443"]:
                dst = GeneratePublicIp()
            elif dpt in ["67","68","53","137","139","123"]:
                dst = random.choice(["172.16.0.2","172.16.0.1","172.16.0.3"])
            elif dpt == "25":
                dst = random.choice(["172.16.1.2","172.16.1.3"])
            else:
                dst = "172." + str(random.randint(16,32)) + "." + str(random.randint(1,254) )+ "." +str(random.randint(1,254))
            Log = CEF.replace("$dst", dst).replace("$proto", proto).replace("$app", app).replace("$act",act).replace("$src",src).replace("$spt",spt).replace("$dpt",dpt).replace("$suser",suser).replace("$shost",shost)
            print(Log)
            SendData(Log)
            if dpt in ["80","443"] and ("5" in str(datetime.datetime.now().minute) or "9" in str(datetime.datetime.now().minute)) and "4" in spt and ("7" not in dst or "3" not in dst) and dst == "172.16.2.2":
                CheckPointSD(src, spt, dst, dpt, app, proto, shost, suser)
                WriteToApacheLog(src, dst, dpt, suser,1)
            elif dpt in ["80","443"] and ("2" in str(datetime.datetime.now().minute) or "9" in str(datetime.datetime.now().minute)) and "4" in spt and ("7" not in dst or "3" not in dst):
                CheckPointSD(src, spt, dst, dpt, app, proto, shost, suser)
            elif dst == "172.16.2.2":
                WriteToApacheLog(src, dst, dst, suser,0)
        except Exception as e:
            print(e)
        time.sleep(random.randint(1,2))

def WriteToApacheLog(src, dst, dpt, suser, flag):
    path = "/var/log/apache2/access.log"
    Log = "$src - $suser " + str(ApacheTimestamp()) + " \"$method $uri $httpversion\" $code $size \"$referer\" \"$useragent\""
    httpver = ["HTTP/1.1","HTTP/2","HTTP/1.1","HTTP/1.1"]
    httpmethods = ["GET","GET","GET","GET","GET","GET","GET","GET","GET","GET","GET","GET","GET","POST","POST","POST","HEAD","PUT","TRACE","DELETE","OPTIONS"]
    httpcodes = ["100","100","101","200","200","200","200","200","200","200","200","200","200","200","200","200","200","200","200","200","200","200","200","201","202","202","202","202","204","301","302","302","302","302","304","400","401","403","404","405","408","500","500","501","502","503","503","503","504","504"]
    if flag == 0:
        uri = uris[random.randint(0,len(uris)-1)].replace("\n","")
        httpcode = random.choice(httpcodes)
    else:
        uri = webpath[random.randint(0,len(webpath)-1)].replace("\n","")
        httpcode = "404"
    method = random.choice(httpmethods)
    httpversion = random.choice(httpver)
    size = random.randint(100,999999)
    useragent = useragents[random.randint(0,len(useragents)-1)].replace("\n","")
    if dpt == "80":
        referer = "http://" + dst + uris[random.randint(0,len(uris)-1)].replace("\n","")
    else:
        referer = "https://" + dst + uris[random.randint(0,len(uris)-1)].replace("\n","")
    Log = Log.replace("$src",src).replace("$suser",suser).replace("$method",method).replace("$uri",uri).replace("$httpversion",httpversion).replace("$code",httpcode).replace("$size",str(size)).replace("$referer",referer).replace("$useragent",useragent)
    print(Log)
    with open(path, 'a') as file:
        file.write(Log+"\n")
        print("Writren to " + path)

def CheckPointSD(src, spt, dst, dpt, app, proto, shost, suser):
    CEF = "CEF:0|Check Point|SmartDefense|Check Point|IPS|$name|$sev| msg=$name act=$act spt=$spt dpt=$dpt dst=$dst src=$src app=$app suser=$suser shost=$shost proto=$proto"
    actions = ["pass","block","block","block"]
    severity = ["Critical","High","High","Medium","Medium","Medium","Medium","Medium","Medium","Low","Low","Low"]
    act = actions[random.randint(0,len(actions)-1)]
    name = ipssignatures[random.randint(0,len(ipssignatures)-1)].replace("\n","")
    sev = random.choice(severity)
    Log = CEF.replace("$sev",sev).replace("$msg", name).replace("$name", name).replace("$dst", dst).replace("$proto", proto).replace("$app", app).replace("$act",act).replace("$src",src).replace("$spt",spt).replace("$dpt",dpt).replace("$suser",suser).replace("$shost",shost)
    print(Log)
    SendData(Log)

#region load
try:
    LoadConfig()
except Exception as e:
    print(e)
#endregion

#starting multiple threads to send data in parallel
thread1 = threading.Thread(target=CheckPointFW, args=())
thread2 = threading.Thread(target=CheckPointFW, args=())
thread3 = threading.Thread(target=CheckPointFWScan, args=())
thread1.start()
time.sleep(0.3)
thread2.start()
time.sleep(0.3)
thread3.start()







