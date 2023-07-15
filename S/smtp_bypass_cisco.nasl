#
# (C) Tenable Network Security, Inc.
#

include( 'compat.inc' );

if(description)
{
  script_id(10520);
  script_version("1.28");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/24");
  script_cve_id("CVE-2000-1022");
  script_bugtraq_id(1698);

  script_name(english:"Cisco PIX Firewall Mailguard Feature SMTP Content Filter Bypass");

  script_set_attribute(attribute:'synopsis', value:
'The remote service is vulnerable to an access control breach.');

  script_set_attribute(attribute:'description', value:
'The remote SMTP server seems to be protected by a content
filtering firewall probably Cisco\'s PIX.

However, an attacker may bypass this content filtering
by issuing a DATA command before a MAIL command,
that allows him to directly communicate with the real SMTP daemon.');
  script_set_attribute(attribute:'see_also', value:'https://seclists.org/bugtraq/2000/Sep/376');
  script_set_attribute(attribute:'see_also', value:'http://www.nessus.org/u?236b35d2');
  script_set_attribute(attribute:'solution', value:
'Upgrade to the relevant fixed version referenced in Cisco bug ID CSCdr91002 and CSCds30699');
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2000-1022");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_publication_date", value: "2000/10/04");
  script_set_attribute(attribute:"vuln_publication_date", value: "2000/09/19");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Firewalls");

  script_copyright(english:"This script is Copyright (C) 2000-2022 Tenable Network Security, Inc.");

  script_dependencies("find_service1.nasl", "smtpserver_detect.nasl", "sendmail_expn.nasl");
  script_exclude_keys("SMTP/wrapped", "SMTP/qmail", "SMTP/postfix");
  script_require_ports("Services/smtp", 25);
  exit(0);
}

include('smtp_func.inc');
include('debug.inc');

var port, state, soc, data, cmd, line_recv, report;

port = get_kb_item("Services/smtp");
if(!port)port = 25;
if (get_kb_item('SMTP/'+port+'/broken')) exit(0, 'The web server on port ' +port+ ' is broken.');

state = get_port_state(port);
if (!get_port_state(port)) audit(AUDIT_PORT_CLOSED, port);

soc = open_sock_tcp(port);
if(!soc) audit(AUDIT_SOCK_FAIL, port);

data = smtp_recv_banner(socket:soc);
if(data && preg(string:data, pattern:"^220.*"))
{
  dbg::log(src:SCRIPT_NAME , msg:'SMTP Banner :', ddata:data);

  cmd = 'HELP\r\n';
  send(socket:soc, data:cmd);
  dbg::log(src:SCRIPT_NAME, msg:'Outgoing Packet :', ddata:cmd);

  line_recv = recv_line(socket:soc, length:1024);
  dbg::log(src:SCRIPT_NAME, msg:'Incoming Packet :', ddata:line_recv);

  if(preg(string:line_recv, pattern:"^500.*"))
  {
    cmd = 'DATA\r\n';
    send(socket:soc, data:cmd);
    dbg::log(src:SCRIPT_NAME, msg:'Outgoing Packet :', ddata:cmd);

    line_recv = recv_line(socket:soc, length:1024);
    dbg::log(src:SCRIPT_NAME, msg:'Incoming Packet :', ddata:line_recv);

    cmd = 'HELP\r\n';
    line_recv = recv_line(socket:soc, length:1024);
    dbg::log(src:SCRIPT_NAME, msg:'Incoming Packet :', ddata:line_recv);

    if(preg(string:line_recv, pattern:"^214.*"))
    {
      report = '\nNessus has detected the remote SMTP server on port ' + port +
      'is vulnerable to an access control breach.\n\n';

      security_report_v4(port:port, severity:SECURITY_HOLE, extra:report);
      close(soc);
    }
  }
}

close(soc);

audit(AUDIT_LISTEN_NOT_VULN, 'SMTP server', port);