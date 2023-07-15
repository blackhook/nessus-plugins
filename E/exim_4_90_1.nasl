#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(107149);
  script_version("1.12");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/05");

  script_cve_id("CVE-2018-6789");
  script_bugtraq_id(103049);
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/05/03");
  script_xref(name:"CEA-ID", value:"CEA-2020-0129");

  script_name(english:"Exim < 4.90.1 Buffer Overflow RCE Vulnerability");

  script_set_attribute(attribute:"synopsis", value:
"The remote mail server is potentially affected by a buffer overflow
vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its banner, the version of Exim running on the remote
host is prior to 4.90.1. It is, therefore, potentially affected by a
buffer overflow vulnerability. A flaw exists base64d() function due to
improper validation of parsed messages. A remote attacker could
potentially cause a buffer overflow condition and execute arbitrary code.");
  script_set_attribute(attribute:"see_also", value:"https://seclists.org/oss-sec/2018/q1/133");
  script_set_attribute(attribute:"see_also", value:"http://exim.org/static/doc/security/CVE-2018-6789.txt");
  script_set_attribute(attribute:"see_also", value:"ftp://ftp.exim.org/pub/exim/exim4/ChangeLog");
  # https://devco.re/blog/2018/03/06/exim-off-by-one-RCE-exploiting-CVE-2018-6789-en/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?4e4be781");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Exim 4.90.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-6789");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:"CANVAS");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/02/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/02/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/03/06");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:exim:exim");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"SMTP problems");

  script_copyright(english:"This script is Copyright (C) 2018-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("smtpserver_detect.nasl");
  script_require_keys("Settings/ParanoidReport");
  script_require_ports("Services/smtp", 25);

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("smtp_func.inc");

if (report_paranoia < 2) audit(AUDIT_PARANOID);

port = get_service(svc:"smtp", default:25, exit_on_fail:TRUE);

banner = get_smtp_banner(port:port);
if (!banner) audit(AUDIT_NO_BANNER, port);
if ("Exim" >!< banner) audit(AUDIT_NOT_LISTEN, 'Exim', port);

matches = pregmatch(pattern:"220.*Exim ([0-9\._]+)", string:banner);
if (isnull(matches)) audit(AUDIT_SERVICE_VER_FAIL, 'Exim', port);

version = matches[1];
# Underscore was added to the vesion
version = ereg_replace(string:version, pattern:"_", replace:".");

if (
     version =~ "^[0-3]\." ||
     version =~ "^4\.([0-8][0-9]|90([^0-9.]|$))"
   )
{
  report =
    '\n  Banner            : ' + banner +
    '\n  Installed version : ' + version +
    '\n  Fixed version     : 4.90.1';

  security_report_v4(port:port, severity:SECURITY_HOLE, extra:report);
}
else audit(AUDIT_LISTEN_NOT_VULN, 'Exim', port, version);
