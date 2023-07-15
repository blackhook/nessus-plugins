#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(106843);
  script_version("1.6");
  script_cvs_date("Date: 2018/12/14 16:35:54");

  script_cve_id("CVE-2017-1731","CVE-2017-1741");
  script_bugtraq_id(102911);

  script_name(english:"IBM WebSphere Application Server 7.0.0.0 < 7.0.0.45 / 8.0.0.0 < 8.0.0.15 / 8.5.0.0 < 8.5.5.14 / 9.0.0.0 < 9.0.0.7 Admin Console Unspecified Insecure Security Remote Privilege Escalation");
  script_summary(english:"Reads the version number from the SOAP and GIOP services.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web application server is affected by a privilege
escalation vulnerability.");
  script_set_attribute(attribute:"description", value:
"The IBM WebSphere Application Server running on the remote host is
version 7.0.0.0 prior to 7.0.0.45, 8.0.0.0 prior to 8.0.0.15, 8.5.0.0
prior to 8.5.5.14, or 9.0.0.0 prior to 9.0.0.7. It is, therefore,
affected by an unspecified privilege escalation vulnerability in the
Admin Console. An authenticated, remote attacker can exploit this to
gain elevated privileges.");
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg22012342");
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg22012345");
  script_set_attribute(attribute:"solution", value:
"Apply IBM WebSphere Application Server version 7.0 Fix Pack 45
(7.0.0.45) (targeted availability 2Q 2018) / 8.0 Fix Pack 15
(8.0.0.15) (targeted availability 2Q 2018) / 8.5 Fix Pack 14
(8.5.5.14) (targeted availability 3Q 2018) / 9.0 Fix Pack 7
(9.0.0.7) (targeted availability 1Q 2018) or later. Alternatively,
upgrade to the minimal fix pack levels required by the interim fix and
then apply Interim Fix PI89498.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/01/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/01/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/02/15");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:websphere_application_server");
  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2018 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("websphere_detect.nasl");
  script_require_ports("Services/www", 8880, 8881, 9001);
  script_require_keys("www/WebSphere", "Settings/ParanoidReport");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

if (report_paranoia < 2) audit(AUDIT_PARANOID);

port = get_http_port(default:8880, embedded:FALSE);

version = get_kb_item_or_exit("www/WebSphere/"+port+"/version");
source = get_kb_item_or_exit("www/WebSphere/"+port+"/source");

app_name = "IBM WebSphere Application Server";

if (version =~ "^([789](\.0)?|8\.5)$")
  audit(AUDIT_VER_NOT_GRANULAR, app_name, port, version);

fix = FALSE; # Fixed version for compare
min = FALSE; # Min version for branch
pck = FALSE; # Fix pack name (tacked onto fix in report)
itr = "PI89498"; # Interim fix

if (version =~ "^9\.0\.")
{
  min = '9.0.0.0';
  fix = '9.0.0.7';
  pck = " (Fix Pack 7)";
}
else if (version =~ "^8\.5\.")
{
  min = '8.5.0.0';
  fix = '8.5.5.14';
  pck = " (Fix Pack 14)";
}
else if (version =~ "^8\.0\.")
{
  min = '8.0.0.0';
  fix = '8.0.0.15';
  pck = " (Fix Pack 15)";
}
else if (version =~ "^7\.0\.")
{
  min = '7.0.0.0';
  fix = '7.0.0.45';
  pck = " (Fix Pack 45)";
}
else
  audit(AUDIT_LISTEN_NOT_VULN, app_name, port, version);

report =
  '\n  Version source    : ' + source  +
  '\n  Installed version : ' + version;

if (ver_compare(ver:version, minver:min, fix:fix, strict:FALSE) <  0)
    report +=
      '\n  Fixed version     : ' + fix + pck +
      '\n  Interim fix       : ' + itr;
else audit(AUDIT_LISTEN_NOT_VULN, app_name, port, version);

report += '\n';

security_report_v4(port:port, severity:SECURITY_WARNING, extra:report);
