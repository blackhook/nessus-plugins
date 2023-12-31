#
# (C) Tenable Network Security, Inc.
#

# References:
# RFC 792 Internet Control Message Protocol
# RFC 791 Internet Protocol
#
# How to drop source routed packets.
# On Linux 2.4:
#  sysctl -w net.ipv4.conf.all.accept_source_route=0
#

include( 'compat.inc' );

if(description)
{
  script_id(11834);
  script_version("1.26");
  script_cvs_date("Date: 2019/03/06 18:38:55");

  script_name(english:"Source Routed Packet Weakness");
  script_summary(english:"Send loose source routed IP packets");

   script_set_attribute(
    attribute:'synopsis',
    value:'The remote host accepts loose source routed IP packets.'
  );

  script_set_attribute(
    attribute:'description',
    value:'The remote host accepts loose source routed IP packets.
The feature was designed for testing purpose.

An attacker may use it to circumvent poorly designed IP filtering
and exploit another flaw. However, it is not dangerous by itself.'
  );

  script_set_attribute(
    attribute:'solution',
    value:'Drop source routed packets on this host or on other ingress
routers or firewalls.'
  );

  script_set_attribute(
    attribute:'see_also',
    value:'http://www.faqs.org/faqs/cisco-networking-faq/section-23.html'
  );

  script_set_attribute(attribute:'risk_factor', value:'None');

  script_set_attribute(attribute:"plugin_publication_date", value: "2003/09/09");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_copyright(english:"This script is Copyright (C) 2003-2019 Tenable Network Security, Inc.");
  script_family(english:"Firewalls");
  exit(0);
}

#
include("misc_func.inc");
include('global_settings.inc');

if(islocalhost())exit(0); # Don't test the loopback interface
if(safe_checks())exit(0); # Some IP stacks are criminally fragile
if(report_paranoia < 1 )exit(0);
if ( TARGET_IS_IPV6 ) exit(0);

srcaddr = compat::this_host();
dstaddr = get_host_ip();
n = 3;	# Number of tries

# Loose source & record route (LSRR)
# Currently, insert_ip_options() is buggy
lsrr = raw_string(	131,	# LSRR
			3,	# Length
			4,	# Pointer
			0);	# Padding


dstport = get_host_open_port();

if (dstport)
{
  srcport = rand() % 64512 + 1024;

  ip = forge_ip_packet(ip_hl: 6, ip_v: 4, ip_tos: 0, ip_id: rand() % 65536,
	ip_off: 0, ip_ttl : 0x40, ip_p: IPPROTO_TCP, ip_src : srcaddr,
	data: lsrr);
  tcp = forge_tcp_packet(ip: ip, th_sport: srcport, th_dport: dstport,
	th_flags: TH_SYN, th_seq: rand(), th_ack: 0, th_off: 5, th_win: 512);

  filter = strcat("src host ", dstaddr, " and dst host ", srcaddr,
	" and tcp and tcp src port ", dstport,
	" and tcp dst port ", srcport);
  r = NULL;
  for (i = 0; i < n && ! r; i ++)
    r = send_packet(tcp, pcap_active: TRUE, pcap_filter: filter);
  if (i < n)
  {
    # No need to associate this flaw with a specific port
    set_kb_item(name: 'Host/accept_lsrr', value: TRUE);
    ihl = 4 * get_ip_element(ip: r, element: "ip_hl");
    if (ihl > 20)
    {
      opt = substr(ip, 20, ihl-1);
      len = ihl - 21;
      for (i = 0; i < len; )
      {
        if (opt[i] == '\x83')
        {
          set_kb_item(name: 'Host/tcp_reverse_lsrr', value: TRUE);
          security_note(port: 0, protocol: "tcp", extra: "
The remote host accepts loose source routed IP packets.
The feature was designed for testing purpose.
An attacker may use it to circumvent poorly designed IP filtering
and exploit another flaw. However, it is not dangerous by itself.

Worse, the remote host reverses the route when it answers to loose
source routed TCP packets. This makes attacks easier.");
          exit(0);
        }
        if (opt[i] == 1) i ++;
        else i += ord(opt[i+1]);
      }
    }
    #set_kb_item(name: 'Host/tcp_reverse_lsrr', value: FALSE);
    security_note(port: 0, protocol: "tcp");
  }
  exit(0);	# Don't try again with ICMP
}

# We cannot use icmp_seq to identifies the datagrams because
# forge_icmp_packet() is buggy. So we use the data instead

filter = strcat("icmp and icmp[0]=0 and src ", dstaddr, " and dst ", srcaddr);

d = rand_str(length: 8);
for (i = 0; i < 8; i ++)
  filter = strcat(filter, " and icmp[", i+8, "]=", ord(d[i]));

seq = 0;
ip = forge_ip_packet(ip_hl: 6, ip_v: 4, ip_tos: 0, ip_id: rand() % 65536,
	ip_off: 0, ip_ttl : 0x40, ip_p: IPPROTO_ICMP, ip_src : srcaddr,
	data: lsrr, ip_len: 38);
icmp = forge_icmp_packet(ip: ip, icmp_type:8, icmp_code:0, icmp_seq: seq,
	icmp_id: rand() % 65536, data: d);
r = NULL;
for (i = 0; i < n && ! r; i ++)
  r = send_packet(icmp, pcap_active: TRUE, pcap_filter: filter);
if (i < n)
{
 set_kb_item(name: 'Host/accept_lsrr', value: TRUE);
 security_note(port: 0, protocol: "icmp");
}
