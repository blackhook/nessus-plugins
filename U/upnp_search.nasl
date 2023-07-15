#TRUSTED 72b259834da5f81f93a5e6019384e1dc82f7c4def6a3b54c28ef0a531edb652b9ca4209e04a43e4dcfdf28be7e8ac620c12eddaf8c35993710c6cbc25d92365369686b26a88e5076bb4d51fc39480d155435487ae2314dd37b8fee363515a26d4d76517a27732cb3cae598bf1cdc9749ced08efd0f7cafd5ad8ad2c1c4068c1529d8c900d2aa204e5ac109746349de59c71893f63ba5308be7304d16d908023585ad01bc9381737dbf92b4e762b5bededd54c6297ce4d31bff7fd3356c8a01a138777dffdfa96f753ae3fd1bc915533d8ba1f12f5e1abc0721c2582d5629a34cd8ccf0d7a3ced8c60d0d3d7e6761e41720e6df17b681c5c76ca6ae363a675f5cd96a5b8a69ca39839e369b6e108fed7cf8261ebb533f784206816349f4d7e04716e09e0b5b679c9e9c3115940003fc985030270657bb71030a7e5ab865aacb79e93daa5131ca5b5eef71178d2b9c1db3ff0bea3a2b74b771f9da5e7487a7f2b85e095470e14719bea48245a192a4f55968584b07db9e4c894319a0f0771bb2aea7bd085c3442678ccc069a3a678a122ae042ccbdf63650d93d2c82af2f3d01c11b55a7f1b34de355916b571a1e9f7e513794fbfbc494db2556c65b64ed6cf53f99159ec9bed5e834299ac1340de42d21ea07c82fdfaedbec4b6034515ad87b3393f04c2744bd7eb9acac447b663da60bbe15be80ed63ef13f6db4a7352b178fe

##
# (C) Tenable, Inc.
##

include("compat.inc");

if(description)
{
 script_id(35711);
 script_version("1.14");
 script_set_attribute(attribute:"plugin_modification_date", value:"2018/09/12");

 script_name(english: "Universal Plug and Play (UPnP) Protocol Detection");
 script_summary(english: "Sends a UPnP M-SEARCH request.");

 script_set_attribute(attribute:"synopsis", value:
"The remote device supports UPnP.");
 script_set_attribute(attribute:"description", value:
"The remote device answered an SSDP M-SEARCH request. Therefore, it
supports 'Universal Plug and Play' (UPnP). This protocol provides
automatic configuration and device discovery. It is primarily intended
for home networks. An attacker could potentially leverage this to
discover your network architecture.");
 script_set_attribute(attribute:"see_also", value:"https://en.wikipedia.org/wiki/Universal_Plug_and_Play");
 script_set_attribute(attribute:"see_also", value:"https://en.wikipedia.org/wiki/Simple_Service_Discovery_Protocol");
 script_set_attribute(attribute:"see_also", value:"http://quimby.gnus.org/internet-drafts/draft-cai-ssdp-v1-03.txt");
 script_set_attribute(attribute:"solution", value:
"Filter access to this port if desired.");
 script_set_attribute(attribute:"risk_factor", value: "None");

 script_set_attribute(attribute:"plugin_publication_date", value: "2009/02/19");

 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_family(english: "Service detection");

 script_copyright(english:"This script is Copyright (C) 2009-2018 and is owned by Tenable, Inc. or an Affiliate thereof.");

 exit(0);
}

include('global_settings.inc');
include('misc_func.inc');
include('audit.inc');
include('agent.inc');

if (agent()) exit(0,"This plugin is disabled on Nessus Agents.");

if (TARGET_IS_IPV6) exit(0, "This plugin does not support IPV6 hosts.");
if (!get_udp_port_state(1900)) audit(AUDIT_PORT_CLOSED, 1900, 'UDP');

##
# This function extracts the advertised URL. If the ip address in the URL matches
# the host address then we will try to register it as a 'www' service.
#
# @param response - The response to the M-SEARCH request
# @param location - The regex match to a location-type field
# @return the parsed URL (ie http://192.168.1.1:9090/gateway.xml)
##
function parse_location(response, location)
{
    location = chomp(location[1]);
    local_var address = pregmatch(string:response, pattern:'http[s]?://(\\d+\\.\\d+.\\d+\\.\\d+):(\\d+)', icase:TRUE);
    if (!isnull(address) && len(address) == 3)
    {
        set_kb_item(name:'upnp/location', value:location);
        return location;
    }
    return NULL;
}

bind_result = bind_sock_udp();
if (isnull(bind_result)) audit(AUDIT_SOCK_FAIL, "udp");

msearch = 'M-SEARCH * HTTP/1.1\r\n' +
          'HOST: 239.255.255.250:1900\r\n' +
          'MAN: "ssdp:discover"\r\n' +
          'MX: 1\r\n' +
          'ST: ssdp:all\r\n' +
          '\r\n';

responses = make_list();
for (i = 0; i < 3 && len(responses) == 0; i++)
{
    # From what I've seen, there are a variety of uPnP servers that will only
    # respond if the destination address is the multicast address. However,
    # there are others that will respond to a direct (ie host ip) request.
    # Since Nessus scans can go beyond the range of the multicast address, and
    # we still want all responses if the host is within multicast range, we will
    # just fire off two requests here.
    sendto(socket:bind_result[0], data:msearch, dst:'239.255.255.250', port:1900);
    sendto(socket:bind_result[0], data:msearch, dst:get_host_ip(), port:1900);

    # look for a response. Since this is UDP we will attempt to resend this
    # if we get no response. We also set a timeout that matches the MX record
    # in our M-SEARCH request
    resp = recvfrom(socket:bind_result[0], port:bind_result[1], src:get_host_ip(), timeout:1);
    while(!isnull(resp))
    {
        if (resp[1] ==  get_host_ip()) responses = make_list(responses, resp[0]);
        resp = recvfrom(socket:bind_result[0], port:bind_result[1], src:get_host_ip(), timeout:1);
    }
}

close(bind_result[0]);
if (len(responses) == 0) audit(AUDIT_NOT_LISTEN, "UPnP", 1900, "UDP");
else register_service(port: 1900, ipproto: "udp", proto: "ssdp");

# Combine any duplicates due to UDP madness.
responses = list_uniq(responses);

# For each entry find the 'location', 'SECURELOCATION.UPNP.ORG', 'server',
# and 'urn'.
locations = make_list();
servers = make_list();
usns = make_list();
foreach(response in responses)
{
    set_kb_item(name: 'upnp/m-search', value: chomp(response));

    location = pregmatch(string:response, pattern:'\r\nLOCATION:[ ]*(.+)\r\n', icase:TRUE);
    if (!isnull(location))
    {
        location = parse_location(response:response, location:location);
        if(!isnull(location)) locations = make_list(locations, location);
    }

    location = pregmatch(string:response, pattern:'\r\nSECURELOCATION.UPNP.ORG:[ ]*(.+)\r\n', icase:TRUE);
    if (!isnull(location))
    {
        location = parse_location(response:response, location:location);
        if(!isnull(location)) locations = make_list(locations, location);
    }

    server = pregmatch(string:response, pattern:'\r\nSERVER:[ ]*(.+)\r\n', icase:TRUE);
    if (!isnull(server))
    {
        server = chomp(server[1]);
        servers = make_list(servers, server);
        set_kb_item(name:'upnp/server', value:server);
    }

    usn = pregmatch(string:response, pattern:'\r\nUSN:[ ]*(.+)\r\n', icase:TRUE);
    if (!isnull(usn))
    {
        if ('::' >< usn[1])
        {
            # Only list URN that have the interface they are implementing. For ex:
            # uuid:9764ead3-00d3-5576-9c4a-9d6895a4cd57::upnp:rootdevice
            usn = chomp(usn[1]);
            usns = make_list(usns, usn);
        }
    }
}

report = 'The device responded to an SSDP M-SEARCH request with the following locations :\n\n';
locations = list_uniq(locations);
foreach(location in locations)
{
    report += ('    ' + location + '\n'); 
}

report += '\nAnd advertises these unique service names :\n\n';
usns = list_uniq(usns);
foreach(usn in usns)
{
    report += ('    ' + usn + '\n'); 
}
report += '\n';

security_report_v4(port:1900,
                   proto:"udp",
                   severity:SECURITY_NOTE,
                   extra:report);
