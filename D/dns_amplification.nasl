#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
  script_id(35450);
  script_version("1.16");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/08/21");

  script_cve_id("CVE-2006-0987");

  script_name(english:"DNS Server Spoofed Request Amplification DDoS");

  script_set_attribute(attribute:"synopsis", value:
"The remote DNS server could be used in a distributed denial of service attack." );
  script_set_attribute(attribute:"description", value:
"The remote DNS server answers to any request.  It is possible to query the name servers (NS) of the root zone ('.') and
get an answer that is bigger than the original request.  By spoofing the source IP address, a remote attacker can
leverage this 'amplification' to launch a denial of service attack against a third-party host using the remote DNS
server." );
  script_set_attribute(attribute:"see_also", value:"https://isc.sans.edu/diary/DNS+queries+for+/5713" );
  script_set_attribute(attribute:"solution", value:
"Restrict access to your DNS server from public network or reconfigure it to reject such queries." );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2006-0987");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_publication_date", value: "2009/01/22");
  script_set_attribute(attribute:"vuln_publication_date", value:"2006/02/28");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2009-2020 Tenable Network Security, Inc.");
  script_family(english:"DNS");

  script_dependencies("dns_server.nasl");
  script_require_keys("DNS/udp/53");

  exit(0);
}

include('network_func.inc');
include('dns_func.inc');
include('byte_func.inc');
include('debug.inc');

port = 53;

if (!get_kb_item('DNS/udp/'+port)) audit(AUDIT_NOT_DETECT, 'DNS', port);

if (report_paranoia < 2 && is_private_addr()) exit(0, 'The target has a private IP address.');

if (!get_udp_port_state(port)) audit(AUDIT_PORT_CLOSED, port);

dns["transaction_id"] = rand() & 0xffff;
dns["flags"]          = 0x0010;
dns["q"]              = 1;

packet = mkdns(dns:dns, query:mk_query(txt:mk_query_txt(""),type:0x0002, class:0x0001));

out_len = strlen(packet);

soc = open_sock_udp(port);
if (!soc) audit(AUDIT_SOCK_FAIL, port);

send(socket:soc, data:packet);
dbg::log(msg:'Outgoing Packet :', ddata:packet);

rsp = recv(socket:soc, length:4096);
dbg::log(msg:'Incoming Packet :', ddata:rsp);

close(soc);

in_len = strlen(rsp);
# The request is 17 bytes long, the answer is 492 bytes long
if (in_len > 2 * out_len)
{
   report = '\nThe DNS query was ' + out_len + ' bytes long, the answer is ' + in_len + ' bytes long.\n';
   security_report_v4(severity:SECURITY_WARNING, port: port, proto: 'udp', extra: report);
}
