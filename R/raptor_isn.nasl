#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

# Script audit and contributions from Carmichael Security
#      Erik Anderson <eanders@carmichaelsecurity.com> (nb: domain no longer exists)
#      Added link to the Bugtraq message archive
#

include('deprecated_nasl_level.inc');
include('compat.inc');
include('debug.inc');

if (description)
{
  script_id(11057);
  script_version("1.39");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/11/11");

  script_cve_id("CVE-2002-1463");
  script_bugtraq_id(5387, 8652);

  script_name(english:"TCP/IP Initial Sequence Number (ISN) Reuse Weakness");

  script_set_attribute(attribute:"synopsis", value:
"The remote device seems to generate predictable TCP Initial Sequence
Numbers.");
  script_set_attribute(attribute:"description", value:
"The remote host seems to generate Initial Sequence Numbers (ISN) in a weak
manner which seems to solely depend on the source and dest port of the TCP
packets.

An attacker may exploit this flaw to establish spoofed connections to the
remote host.

The Raptor Firewall and Novell NetWare are known to be vulnerable to this
flaw, although other network devices may be vulnerable as well.");
  script_set_attribute(attribute:"see_also", value:"https://seclists.org/bugtraq/2002/Aug/60");
#http://securityresponse.symantec.com/avcenter/security/Content/2002.08.05.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a7411819");
  script_set_attribute(attribute:"solution", value:
"If you are using a Raptor Firewall, install the TCP security hotfix
described in Symantec's advisory.  Otherwise, contact your vendor for
a patch.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2002-1463");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"1995/01/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2002/08/02");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"General");

  script_copyright(english:"This script is Copyright (C) 2002-2022 Tenable Network Security, Inc.");

  script_require_keys("Settings/ThoroughTests");

  exit(0);
}

if (!thorough_tests) audit(AUDIT_THOROUGH);
if (TARGET_IS_IPV6) audit(AUDIT_ONLY_IPV4);
if (islocalhost()) audit(AUDIT_LOCALHOST);

var port = get_host_open_port();
if(!port)audit(AUDIT_PORT_CLOSED, port);

var ip1 = forge_ip_packet(
        ip_hl: 5,
        ip_v: 4,
        ip_tos: 0,
        ip_id: rand(),
        ip_off: 0,
        ip_ttl: 64,
        ip_p: IPPROTO_TCP,
        ip_src: compat::this_host()
        );

var ip2 = forge_ip_packet(
        ip_hl: 5,
        ip_v: 4,
        ip_tos: 0,
        ip_id: rand(),
        ip_off: 0,
        ip_ttl: 64,
        ip_p: IPPROTO_TCP,
        ip_src: compat::this_host()
        );

var s1 = rand();
var s2 = rand();

var tcp1 = forge_tcp_packet(ip:ip1,
                            th_sport: 1500,
                            th_dport: port,
                            th_flags:TH_SYN,
                            th_seq: s1,
                            th_ack: 0,
                            th_x2: 0,
                            th_off: 5,
                            th_win: 8192,
                            th_urp: 0);

var tcp2 = forge_tcp_packet(ip:ip1,
                            th_sport: 1500,
                            th_dport: port,
                            th_flags:TH_SYN,
                            th_seq: s2,
                            th_ack: 0,
                            th_x2: 0,
                            th_off: 5,
                            th_win: 0,
                            th_urp: 0);

s1 = s1 + 1;
s2 = s2 + 1;

var filter = "tcp and src " + get_host_ip() + " and dst port " + 1500;
var r1 = send_packet(tcp1, pcap_active:TRUE, pcap_filter:filter);

dbg::log(src:SCRIPT_NAME, msg:'Outgoing Packet 1 :', ddata:r1);

if(!isnull(r1))
{
  # Got a reply - extract the ISN
  var isn1 = get_tcp_element(tcp:r1, element:"th_seq");
  if(isn1 == 0 || isnull(isn1)) audit(AUDIT_PORT_CLOSED, port);
  var ack1  = get_tcp_element(tcp:r1, element:"th_ack");

  var rst1 = forge_tcp_packet(ip:ip1,
  		                      	th_sport:1500,
				                      th_dport: port,
				                      th_flags: TH_RST,
				                      th_seq: ack1,
				                      th_ack:0,
				                      th_x2: 0,
				                      th_off: 5,
				                      th_win: 0,
				                      th_urp: 0);

  send_packet(rst1, pcap_active:FALSE);
  var r2 = send_packet(tcp2, pcap_active:TRUE, pcap_filter:filter);

  dbg::log(src:SCRIPT_NAME, msg:'Outgoing Packet 2 :', ddata:r2);

  if(!isnull(r2))
  {
    # Send the second request
    var isn2 = get_tcp_element(tcp:r2, element:"th_seq");
    if(isn2 == 0 || isnull(isn2)) audit(AUDIT_PORT_CLOSED, port);
    var ack2 = get_tcp_element(tcp:r2, element:"th_ack");
    if(!(ack2 == s2)) exit(1, "Nessus was not able to detect predictable TCP Initial Sequence Numbers.");

    dbg::log(src:SCRIPT_NAME, msg:'Initial Sequence Numbers 1 :', ddata:isn1);
    dbg::log(src:SCRIPT_NAME, msg:'Initial Sequence Numbers 2 :', ddata:isn2);

    if(isn1 == isn2)
    {
      var report  = '\nNessus was able to detect predictable TCP Initial Sequence Numbers by sending the following request\n\n' +
      isn1 + isn2 + '\n\n';

      security_report_v4(port:port, severity:SECURITY_HOLE, extra:report);
    }
  }
}




