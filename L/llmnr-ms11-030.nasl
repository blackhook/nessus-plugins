#TRUSTED 55cb99c9413f0a3cd642c6263a373dcf04273ea132f5a2af49c63bac281cc696c923b5954553855803458443b3ca1b8c6f8da0a4e2957172ec8d2791a49f51fee13ed2d542850b3dd4e931ca230cf9c612cb61e8fbffde6d3acc9c362b9dffde46e536b7de36a602f5be4d1005277a8638af5662932ef1da83e26d32c5c4087571f89b97c196e24060bdede7b84777423189cae941d6832923298406fd0f49679eb1f328487eafb708eb55c25786497a6359a3dc8df5e01b4bb848f6ea471958afd71284b7ff8cba209aae0702ac57517d5b1d004c6d174fbced4ba5cbece5104fc00d209df70981eed4221ac6f1376b2014c7a0389a8a09247263e485b00ae07a6b98d43cb48b5e85110189392f95d88a94c48b72b0a590b2d2085ba70de633413a2a055d19269cc2712d8fd512963c75a11ea75fe17096bbc86cb1158b22a11bb0fc2e038fd6a7fe4d92a0b2edbc7e419347099b40dfcc67dba436e730e069a13c7282738780f7cdf64f530aa5efcf085a1773cc6527fa0c1276ffafef0c4ba4dd1c23d348e5dabfbf4672333bae615d4941cf0b788b641a995fad284ad6129bab0bf3b1bbb0d637b441c1583ded3e8ebac5882cd85c6859f2640963045fd72b5af3c4d7057720f7eef91172f547926c9671a65f4bcef64fd3d0844b53882b4017eb9f12d1c7b90918f1d638651deb23a91dd660d916357de45a3948f8979b
#
# (C) Tenable Network Security, Inc.
#

if (! defined_func("get_local_mac_addr")) exit(0);
if (! defined_func("inject_packet")) exit(0);

include("compat.inc");

if (description)
{
 script_id(53514);
 script_version("1.18");
 script_set_attribute(attribute:"plugin_modification_date", value:"2020/08/05");

  script_cve_id("CVE-2011-0657");
 script_bugtraq_id(47242);
 script_xref(name:"IAVA", value:"2011-A-0039-S");
 script_xref(name:"MSFT", value:"MS11-030");
 script_xref(name:"MSKB", value:"2509553");

 script_name(english:"MS11-030: Vulnerability in DNS Resolution Could Allow Remote Code Execution (2509553) (remote check)");
 script_summary(english:"Checks if the DNS resolution supports invalid addresses");

 script_set_attribute(attribute:"synopsis", value:
"Arbitrary code can be executed on the remote host through the
installed Windows DNS client.");
 script_set_attribute(attribute:"description", value:
"A flaw in the way the installed Windows DNS client processes Link-
local Multicast Name Resolution (LLMNR) queries can be exploited to
execute arbitrary code in the context of the NetworkService account.

Note that Windows XP and 2003 do not support LLMNR and successful
exploitation on those platforms requires local access and the ability
to run a special application. On Windows Vista, 2008, 7, and 2008 R2,
however, the issue can be exploited remotely.");
  # https://docs.microsoft.com/en-us/security-updates/SecurityBulletins/2011/ms11-030
  script_set_attribute(attribute:"see_also", value:"https://www.nessus.org/u?361871b1");
 script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows XP, 2003, Vista,
2008, 7, and 2008 R2.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2011-0657");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"metasploit_name", value:'Microsoft Windows DNSAPI.dll LLMNR Buffer Underrun DoS');
 script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
 script_set_attribute(attribute:"exploit_framework_core", value:"true");

 script_set_attribute(attribute:"vuln_publication_date", value:"2011/04/12");
 script_set_attribute(attribute:"patch_publication_date", value:"2011/04/12");
 script_set_attribute(attribute:"plugin_publication_date", value:"2011/04/21");

 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
 script_set_attribute(attribute:"stig_severity", value:"I");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2011-2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

 script_require_keys("Services/udp/llmnr");

 script_dependencies('llmnr-detect.nasl');
 exit(0);
}

include("global_settings.inc");
include('misc_func.inc');
include('raw.inc');

# Get the port
port = get_service(svc:'llmnr', ipproto:"udp", default:5355, exit_on_fail:TRUE);
if (!get_udp_port_state(port)) exit(0, "UDP port "+port+" is not open.");

if (islocalhost()) exit(1, "Can't check against localhost.");
if (!islocalnet()) exit(1, "Host isn't on a local network.");

# Build and send a query
question = 'in-addr.arpa';
split_address = split(get_host_ip(), sep:'.', keep:FALSE);
foreach octet(split_address)
  question = octet + 'a.' + question;

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
  exit(1, "Couldn't get the local MAC address.");
remote   = get_gw_mac_addr(); # MAC Address of the remote host
if(!remote)
  exit(1, "Couldn't get the target MAC address.");

# Open the port to listen to the response
bind_result = bind_sock_udp();
if(isnull(bind_result)) exit(1, "Couldn't create a UDP listener.");
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

# If the host didn't respond, it probably isn't vulnerable
if(isnull(response) || response == '')
  exit(0, "The host didn't respond - it likely is not affected.");

# Check that the message was successful
if(!(getword(blob:response, pos:2) & 0x8000))
  exit(1, "Didn't receive a valid response from the remote LLMNR server.");

security_hole(port:port, proto:"udp");

