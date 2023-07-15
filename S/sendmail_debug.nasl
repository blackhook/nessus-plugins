#
# (C) Tenable Network Security, Inc.
#

# MA 2004-12-29: I merge sendmail_wiz.nasl into this one

include("compat.inc");

if (description)
{
  script_id(10247);
  script_version("1.32");
  script_cvs_date("Date: 2018/09/17 21:46:53");

  script_cve_id("CVE-1999-0095", "CVE-1999-0145");
  script_bugtraq_id(1, 2897);

  script_name(english:"Sendmail DEBUG/WIZ Remote Command Execution");
  script_summary(english:"Checks for the presence of DEBUG or WIZ commands");

  script_set_attribute(attribute:"synopsis", value:"Arbitrary commands may be run on this server.");
  script_set_attribute(attribute:"description", value:
"Your MTA accepts the DEBUG or WIZ command. It may be an old version
of Sendmail.

This command is dangerous as it allows remote users to execute
arbitrary commands as root without the need to log in.");
  script_set_attribute(attribute:"solution", value:"Upgrade your MTA.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-1999-0095");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"1983/11/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"1999/08/22");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:sendmail:sendmail");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 1999-2018 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english: "SMTP problems");

  script_dependencies("sendmail_detect.nbin");
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

reqs = make_list('DEBUG\r\n', 'WIZ\r\n');
rep_report = '';
vuln = FALSE;

foreach req (reqs)
{
  send(socket:soc, data:req);

  rep = recv_line(socket:soc, length:1024);
  if (rep =~ '^2[0-9][0-9][ \t]')
  {
    rep_report += rep;
  }
  rep_report += '\n=================================================\n';
}
close(soc);

if (vuln)
  security_report_v4(port:port, severity:SECURITY_HOLE, request:reqs, output:rep_report);
else audit(AUDIT_INST_VER_NOT_VULN, "Sendmail", app_info['version']);
