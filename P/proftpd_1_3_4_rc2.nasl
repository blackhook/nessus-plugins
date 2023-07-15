#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(106753);
  script_version("1.3");
  script_cvs_date("Date: 2019/11/08");

  script_cve_id("CVE-2011-1137");
  script_bugtraq_id(46183);

  script_name(english:"ProFTPD < 1.3.4rc2 client-hostname restriction bypass");
  script_summary(english:"Checks version of ProFTPD.");

  script_set_attribute(attribute:"synopsis", value:
"The remote FTP server is affected by a Denial of Service
vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote host is using ProFTPD, a free FTP server for Unix and
Linux.
According to its banner, the version of ProFTPD installed on the
remote host is earlier than 1.3.4rc2 and is affected by a Denial
of Service vulnerability in the mod_sftp module.");
  script_set_attribute(attribute:"see_also", value:"http://bugs.proftpd.org/show_bug.cgi?id=3586");
  script_set_attribute(attribute:"solution", value:
"Upgrade to ProFTPD version 1.3.4rc2 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/01/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/04/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/02/12");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:proftpd:proftpd");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"FTP");

  script_copyright(english:"This script is Copyright (C) 2018-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ftp_overflow.nasl", "ftpserver_detect_type_nd_version.nasl");
  script_require_keys("ftp/proftpd", "Settings/ParanoidReport");
  script_require_ports("Services/ftp", 21);

  exit(0);
}

include("audit.inc");
include("ftp_func.inc");
include("global_settings.inc");

if (report_paranoia < 2) audit(AUDIT_PARANOID);

port = get_ftp_port(default: 21, broken:TRUE);

app = "ProFTPD";
banner = get_ftp_banner(port:port);
if (!banner) audit(AUDIT_NO_BANNER, port);
if (app >!< banner) audit(AUDIT_NOT_DETECT, app, port);

matches = pregmatch(string:banner, pattern:"ProFTPD ([0-9a-z.]+) ");
if (isnull(matches)) audit(AUDIT_SERVICE_VER_FAIL, app, port);
version = matches[1];

if (version =~ '^1(\\.3)?$') audit(AUDIT_VER_NOT_GRANULAR, app, version);

if (
  version =~ "^0($|\.)" ||
  version =~ "^1\.[0-2]($|\.)" ||
  version =~ "^1\.3\.[123]($|[^0-9])" ||
  version =~ "^1\.3\.4(rc1)?($|[^0-9a-z])"
)
{
  report =
    '\n  Version source    : ' + chomp(banner) +
    '\n  Installed version : ' + version +
    '\n  Fixed version     : 1.3.4rc2\n';
  security_report_v4(severity:SECURITY_WARNING, port:port, extra:report);
  exit(0);
}
else audit(AUDIT_LISTEN_NOT_VULN, app, port, version);
