#TRUSTED 4bc1e47e59ed2d39ca5d48a56af304811f6b260a22fc7564825c1412220eebe2bc091b6cba43f65d5cba6e009433309addf72a3eff07a425ea9bc55102120cb705fc70d3b000f029727eb03216a9adb4c20bd5e2032c3b3a51ac633df222d40c90b7b5c30a7e84519af355fc1dad7be4296c2374573a4a8fd9be4ac5ec0ebbe657a8d3d0b4766d5b78a254099c7332d3df43d19dff26ccee4569844cbabbf3c95b14366095df92f69c49d4238cc2df62acde3513af7f758f0b4fa955c79ff01aa5a2c8493ea1947889e2a992d23ff69a6529ac36d6a0eb61f1e124d685ba5763efda595fbfb4a1520a810a538978bdb396cc988e5d2ad5b4f81349ff3ea3e7883b228ef1f8b28277c81daf7fa6324b8a6a6ff7cf630ba7815d902bb9c39989b21117dc74327f4dbac77542942b433f8403784a2eb1859e02b22d361b6350e40da9fe0ca71b0f99269b58aaa293f8bff90d761e1a4e2adb1aa32250125c19c3a24b50cc19a49f799a19322f16072b59275b6b399d74078defe0381d2fb3d54cb03062c39f37833a3a69b03d6c2ec83c84381e8ab00a1dc7c8a9b889185b8276a308d31e7e8b25e5df2aa8e8d90edbbbaba6aeec7a279231b6efac087adc63040aeb521fd6e6621d0cdb14c869cb30cbac0b91c136ad01d576c15dd83d1ba40e06b707c85c89b7e6eadac312ffef8eeb34142febe55176bed954140901772e251c
#
# (C) Tenable Network Security, Inc.
#

if (! defined_func("get_local_mac_addr")) exit(0);
if (! defined_func("inject_packet")) exit(0);

include("compat.inc");

if (description)
{
 script_id(53513);
 script_version("1.9");
 script_set_attribute(attribute:"plugin_modification_date", value:"2019/03/06");

 script_name(english: "Link-Local Multicast Name Resolution (LLMNR) Detection");
 script_summary(english: "Sends a LLMNR PTR request");

 script_set_attribute(attribute:"synopsis", value:"The remote device supports LLMNR.");

 script_set_attribute(attribute:"description", value:
"The remote device answered to a Link-local Multicast Name Resolution
(LLMNR) request.  This protocol provides a name lookup service similar
to NetBIOS or DNS.  It is enabled by default on modern Windows
versions.");

 script_set_attribute(attribute:"see_also", value: "http://www.nessus.org/u?51eae65d");
 script_set_attribute(attribute:"see_also", value: "http://technet.microsoft.com/en-us/library/bb878128.aspx");

 script_set_attribute(attribute:"solution", value:
"Make sure that use of this software conforms to your organization's
acceptable use and security policies." );

 script_set_attribute(attribute:"risk_factor", value:"None" );
 script_set_attribute(attribute:"plugin_publication_date", value:"2011/04/21");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2011-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");
 script_family(english: "Service detection");
 exit(0);
}

include("global_settings.inc");
include('misc_func.inc');
include('dns_func.inc');
include('raw.inc');

# The spec says that the port has to be 5355
port = 5355;
if (!get_udp_port_state(port)) exit(0, "UDP port "+port+" is not open.");

if (islocalhost()) exit(1, "Can't check against localhost.");
if (!islocalnet()) exit(1, "Host isn't on a local network.");

# Build and send a query
question = 'in-addr.arpa';
split_address = split(get_host_ip(), sep:'.', keep:FALSE);
foreach octet(split_address)
  question = octet + '.' + question;

# This is basically a standard DNS PTR query
ptr_query = '\x13\x37' + # Transaction ID
            '\x00\x00' + # Flags - none
            '\x00\x01' + # Questions
            '\x00\x00' + # Answers
            '\x00\x00' + # Authority
            '\x00\x00' + # Additional
            mkbyte(strlen(question)) + question + '\x00' + # Question
            '\x00\x0c' + # Type = PTR
            '\x00\x01';  # Class = IN; 



mac_addr = get_local_mac_addr(); # MAC Address of the local host
if(!mac_addr)
  exit(1, "Couldn't get local MAC address.");
remote   = get_gw_mac_addr(); # MAC Address of the remote host
if(!remote)
  exit(1, "Couldn't get target MAC address.");

# Open the port to listen to the response
bind_result = bind_sock_udp();
if(isnull(bind_result)) exit(1, "Couldn't create UDP listener.");
s = bind_result[0];
src_port = bind_result[1];

# Create the packet and put it on the wire
packet = link_layer() + mkpacket(ip(ip_dst:"224.0.0.252", ip_src:compat::this_host(), ip_p:IPPROTO_UDP), udp(uh_dport:5355, uh_sport:src_port), payload(ptr_query));

response = NULL;
for(i = 0; i < 3 && isnull(response); i++)
{
  inject_packet(packet:packet);
  response = recv(socket:s, length:4096, timeout:2);
}

# If the host doesn't answer, it probably isn't running a LLMNR server
if(isnull(response) || response == '')
  exit(0, "The host didn't respond - either it isn't running LLMNR or it has a restrictive configuration.");

# Register the service
register_service(port:port, ipproto:"udp", proto:"llmnr");

# Just for fun, tell them what the hostname is.
response = dns_split(response);

# Get the name and remove the leading size + trailing null
name = response['an_rr_data_0_data'];
name = pregmatch(pattern:"([[:print:]]+)", string:name);
if(!empty_or_null(name) && !empty_or_null(name[1]))
  name = name[1];
else 
  name = NULL;

gs_opt = get_kb_item("global_settings/report_verbosity");
if (gs_opt && gs_opt != 'Quiet' && strlen(name) > 0)
{
  report = '\nAccording to LLMNR, the name of the remote host is \'' + name + '\'.\n';
  security_note(port:port, proto:"udp", extra:report);
}
else security_note(port:port, proto:"udp");
