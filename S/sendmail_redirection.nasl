#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(10250);
  script_version("1.30");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/08/05");

  script_name(english:"Sendmail Redirection Relaying Allowed");
  script_summary(english:"Redirection check");

  script_set_attribute(attribute:"synopsis", value:
"The remote SMTP server is vulnerable to a redirection attack.");
  script_set_attribute(attribute:"description", value:
"The remote sendmail server accepts messages addressed to recipients
of the form 'user@host1@example.com'.  A remote attacker could
leverage this to reach mail servers behind a firewall or to avoid
detection by routing mail through the affected host.");
  script_set_attribute(attribute:"solution", value:
"Consult the Sendmail documentation and modify the server's
configuration file to avoid such redirections.  For example, this may
involve adding the following statement at the top of Ruleset 98, in
sendmail.cf :

  R$*@$*@$*       $#error $@ 5.7.1 $: '551 Sorry, no redirections.'");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N");

  script_set_attribute(attribute:"cvss_score_source", value:"manual");
  script_set_attribute(attribute:"plugin_publication_date", value:"1999/08/25");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:sendmail:sendmail");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 1999-2020 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english: "SMTP problems");

  script_dependencies("sendmail_detect.nbin", "smtp_settings.nasl");
  script_require_keys("installed_sw/Sendmail");
  exit(0);
}

include("vcf.inc");
include("smtp_func.inc");

app_info = vcf::get_app_info(app:"Sendmail");
port = app_info['port'];

if (!get_port_state(port))
  audit(AUDIT_PORT_CLOSED, port);

soc = open_sock_tcp(port);
if (!soc) audit(AUDIT_SOCK_FAIL, port);

if (!smtp_recv_banner(socket:soc))
{
  close(soc);
  audit(AUDIT_NO_BANNER, port);
}

domain = get_kb_item('Settings/third_party_domain');
from_email = get_kb_item('SMTP/headers/From');
if (!domain) domain = 'example.com';
if (!from_email) from_email = 'root@example.com';

req_1 = "HELO " + domain + "\r\n";
send(socket:soc, data:req_1);
recv_line(socket:soc, length:1024);

req_2 = "MAIL FROM: " + from_email + "\r\n";
send(socket:soc, data:req_2);
recv_line(socket:soc, length:1024);

req_3 = "RCPT TO: root@host1@" + domain + "\r\n";
send(socket:soc, data:req_3);
rep_3 = recv_line(socket:soc, length:255);

close(soc);

if (preg(pattern:"^250 .*", string:rep_3))
{
  security_report_v4(port:port, severity:SECURITY_WARNING, cmd:"RCPT TO", request:make_list(req_1, req_2, req_3), output:rep_3);
}
else audit(AUDIT_INST_VER_NOT_VULN, "Sendmail", app_info['version']);
