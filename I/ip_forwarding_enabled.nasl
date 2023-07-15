#TRUSTED a64b1df55e0827aa8fffd1908eb3c1171098bd39d4d07e65804e3b56a989fb1d57f523aba8de089c41bf5255f3b2e5d96b7be53ac27d9718c366ee87963a8c1b9f4c06d8308ace0676fa1a93eae904d1f41bc1f7f40998395ac8f8d3eb6adfb47b85d842e082e70832ca6206f1bab99a034a53183fcbca4e207c86e8f8c0f5b9eabdd1f06350f493a4d442e690dcbb33b5d95730753722b3aaecc7cd7e4032fb0ddcabf14debd40474bcc7723b5bfb68d0b1caecebd5c66aaac40702759764faba1b0af30ced03c51ee727950e9c6289e06c4c5ff6f8b8bec9058a278a1d926ffe38dd7d6039abd86c8238caafc0eac00bfaf36e5cac13da2a8ee74a8247858282e3815e934ea81f76f9e574ae0ba8172c05b3d1fbf085321f7b99b35cca9a21d0db04a598553bf2a6fb10d5bd40dc054359820488be40060588e14874b91c1b2370cd699e1e9b03dbe7cabe07c7a3d1edbe3b6fc179ab33063a23742467f74f83aa85e729484b0d4d468273521eabd37ddf1a312f88c57535e43a9d6e9c6f2bcde3cc42adcf34b1d283eab36c7caece19ab49a0dd175ef5c3a263ee682865fa4f30c1d120132de90fe1d6b3a24f1f0ad5ed48650e93b5e0e9d959b10df174bc6ba67090a835c4490d5ae644d950d786c78740ea72e1b7dbd8f90fbabcb73924284555250f4c982a606de58674d5a1a6e93adba4b7f69c39e2bb3c16aba85109
#
# (C) Tenable Network Security, Inc.
#

if ( ! defined_func("inject_packet") ) exit(0);

include("compat.inc");

if (description)
{
 script_id(50686);
 script_version("1.15");
 script_set_attribute(attribute:"plugin_modification_date", value:"2021/12/29");

 script_cve_id("CVE-1999-0511");

 script_name(english:"IP Forwarding Enabled");
 script_summary(english:"Determines whether IP forwarding is enabled on the remote host.");

 script_set_attribute(attribute:"synopsis", value:
"The remote host has IP forwarding enabled.");
 script_set_attribute(attribute:"description", value:
"The remote host has IP forwarding enabled. An attacker can exploit
this to route packets through the host and potentially bypass some
firewalls / routers / NAC filtering.

Unless the remote host is a router, it is recommended that you disable
IP forwarding.");
 script_set_attribute(attribute:"solution", value:
"On Linux, you can disable IP forwarding by doing :

echo 0 > /proc/sys/net/ipv4/ip_forward

On Windows, set the key 'IPEnableRouter' to 0 under

HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\Tcpip\Parameters

On Mac OS X, you can disable IP forwarding by executing the command :

sysctl -w net.inet.ip.forwarding=0

For other systems, check with your vendor.");
 script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:L/PR:L/UI:N/S:C/C:L/I:L/A:L");
 script_set_attribute(attribute:"cvss_score_source", value:"CVE-1999-0511");

 script_set_attribute(attribute:"vuln_publication_date", value:"1997/01/01");
 script_set_attribute(attribute:"plugin_publication_date", value:"2010/11/23");

 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);

 script_copyright(english:"This script is Copyright (C) 2010-2021 Tenable Network Security, Inc.");
 script_family(english:"Firewalls");

 exit(0);
}

include('raw.inc');
include('debug.inc');

if ( TARGET_IS_IPV6 ) exit(0, "IPv4 check.");
if ( islocalhost() ) exit(0, "Can't check against localhost.");
if ( ! islocalnet() ) exit(1, "Remote host is not on the local network.");
var ll = link_layer();
if ( strlen(ll) < 14 ) exit(0, "Not ethernet.");

var udp_src = rand() % 64000 + 1024;
var udp_dst = rand() % 64000 + 1024;
var src = "169.254." + (rand()%253 + 1) + "." + (rand()%253 + 1);
var smac = get_local_mac_addr();
var dmac = get_gw_mac_addr();

var pkt = mkpacket(ip(ip_p:IPPROTO_UDP, ip_src:src, ip_dst:compat::this_host()), udp(uh_sport:udp_src, uh_dport:udp_dst));
var ethernet = dmac + smac + mkword(0x0800);
var me  = get_local_mac_addr();
var filt = NULL;
for ( i = 0 ; i < 6 ; i ++ )
{
 if ( filt ) filt += " and ";
 filt += "ether[" + i + "] = " + getbyte(blob:me, pos:i) + " ";
}
for ( i = 0 ; i < 3; i ++ )
{
 var r = inject_packet(packet:ethernet + pkt, filter:"udp and src port " + udp_src + " and dst port " + udp_dst + " and src host " + src + " and dst host " + compat::this_host() + " and " + filt , timeout:1);
 if ( r ) break;
}

if ( r )
{
  var local_mac = hexstr(smac);
  var local_res = hexstr(substr(r, 0, 5));
  var gateway_mac = hexstr(dmac);
  var gateway_res = hexstr(substr(r, 6, 11));

  var report = 'IP forwarding appears to be enabled on the remote host.\n\n' +
               ' Detected local MAC Address        : ' + local_mac + '\n' +
               ' Response from local MAC Address   : ' + local_res + '\n\n' +
               ' Detected Gateway MAC Address      : ' + gateway_mac + '\n' +
               ' Response from Gateway MAC Address : ' + gateway_res ;

  if (local_res == local_mac && gateway_res == gateway_mac) security_report_v4(port:0, severity:SECURITY_WARNING, extra:report);
}
else exit(0, "IP forwarding is not enabled on the remote host.");
