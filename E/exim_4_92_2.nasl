#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(128553);
  script_version("1.4");
  script_cvs_date("Date: 2019/10/17 14:31:05");

  script_cve_id("CVE-2019-15846");

  script_name(english:"Exim < 4.92.2 ");
  script_summary(english:"Checks the version of the SMTP banner.");

  script_set_attribute(attribute:"synopsis", value:
"The remote mail server is potentially affected by a remote code
execution vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its banner, the version of Exim running on the remote
host is prior to 4.92.2. It is, therefore, potentially affected by a
remote code execution vulnerability allowing unauthenticated, remote 
attackers to execute arbitrary code as root via a trailing backslash.");
  script_set_attribute(attribute:"see_also", value:"https://exim.org/static/doc/security/CVE-2019-15846.txt");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Exim 4.92.2 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-15846");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/09/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/09/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/09/06");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:exim:exim");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"SMTP problems");

  script_copyright(english:"This script is Copyright (C) 2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("smtpserver_detect.nasl");
  script_require_keys("Settings/ParanoidReport");
  script_require_ports("Services/smtp", 25);

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("smtp_func.inc");

port = get_service(svc:"smtp", default:25, exit_on_fail:TRUE);

banner = get_smtp_banner(port:port);
if (!banner) audit(AUDIT_NO_BANNER, port);
if ("Exim" >!< banner) audit(AUDIT_NOT_LISTEN, 'Exim', port);

matches = pregmatch(pattern:"220.*Exim ([0-9\._]+)", string:banner);
if (isnull(matches)) audit(AUDIT_SERVICE_VER_FAIL, 'Exim', port);

if (report_paranoia < 2) audit(AUDIT_PARANOID);

version = matches[1];
# Underscore was added to the vesion
version = ereg_replace(string:version, pattern:"_", replace:".");

if (ver_compare(ver:version, fix:'4.92.2', strict:FALSE) < 0)
{
  report =
    '\n  Banner            : ' + banner +
    '\n  Installed version : ' + version +
    '\n  Fixed version     : 4.92.2';

  security_report_v4(port:port, severity:SECURITY_HOLE, extra:report);
}
else audit(AUDIT_LISTEN_NOT_VULN, 'Exim', port, version);
