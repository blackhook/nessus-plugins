#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(10248);
  script_version("1.22");
  script_cvs_date("Date: 2018/08/06 17:19:16");

  script_cve_id("CVE-1999-0096");

  script_name(english: "Sendmail decode Alias Arbitrary File Overwrite");
  script_summary(english: "Checks if the remote mail server can be used to overwrite files");

  script_set_attribute(attribute:"synopsis", value:"It might be possible to overwrite arbitrary files on the server.");
  script_set_attribute(attribute:"description", value:
"The remote SMTP server seems to pipe mail sent to the 'decode' alias 
to a program.

There have been in the past a lot of security problems regarding this, 
as it would allow an attacker to overwrite arbitrary files on the remote
server.

We suggest you deactivate this alias.");
  script_set_attribute(attribute:"solution", value:"Remove the 'decode' line in /etc/aliases.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N");

  script_set_attribute(attribute:"cvss_score_source", value:"CVE-1999-0096");
  script_set_attribute(attribute:"vuln_publication_date", value:"1989/05/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"1999/08/30");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:sendmail:sendmail");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 1999-2018 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english: "SMTP problems");

  script_dependencies("sendmail_detect.nbin");
  script_require_keys("installed_sw/Sendmail", "SMTP/expn");
  exit(0);
}

include("vcf.inc");
include("smtp_func.inc");

# EXPN command must be supported.
get_kb_item_or_exit("SMTP/expn");

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

req = "EXPN decode\r\n";
send(socket:soc, data:req);

rep = recv_line(socket:soc, length:1024);

close(soc);

if(preg(pattern:"^250 .*", string:rep))
{
  if("/bin" >< rep)
    security_report_v4(port:port, severity:SECURITY_WARNING, request:req, output:rep);
  else audit(AUDIT_INST_VER_NOT_VULN, "Sendmail", app_info['version']);
}
else audit(AUDIT_INST_VER_NOT_VULN, "Sendmail", app_info['version']);
