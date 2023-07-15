#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(59328);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");
  script_bugtraq_id(53603);

  script_name(english:"Atlassian FishEye 2.5.8 / 2.6.8 / 2.7.12 XML Parsing Vulnerability");

  script_set_attribute(attribute:"synopsis", value:
"The version of Atlassian FishEye installed on the remote host may be
affected by an XML parsing vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the version of Atlassian
FishEye running on the remote host is potentially affected by an XML
parsing vulnerability. This vulnerability may allow an
unauthenticated, remote attacker to perform a denial of service attack
against FishEye. This vulnerability may also allow an unauthenticated,
remote attacker to read any local files that the user can access.");
  # https://confluence.atlassian.com/fisheye/fisheye-and-crucible-security-advisory-2012-05-17-960161734.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?6b7f1aed");
  script_set_attribute(attribute:"see_also", value:"https://jira.atlassian.com/browse/FE-4016");
  script_set_attribute(attribute:"solution", value:
"Upgrade to FishEye 2.5.8 / 2.6.8 / 2.7.12 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/03/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/05/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/06/01");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:atlassian:fisheye");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2012-2022 Tenable Network Security, Inc.");

  script_dependencies("fisheye_detect.nasl");
  script_require_keys("www/fisheye", "Settings/ParanoidReport");
  script_require_ports("Services/www", 8060);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("http.inc");
include("misc_func.inc");
include("install_func.inc");

port = get_http_port(default:8060);

app = "FishEye";
app_name = tolower(app);

get_install_count(app_name:app_name, exit_if_zero:TRUE);

install = get_single_install(
  app_name : app_name,
  port     : port,
  exit_if_unknown_ver : TRUE
);

dir = install['path'];
ver = install["version"];
url = build_url(port:port, qs:dir + "/");

if (report_paranoia < 2) audit(AUDIT_PARANOID);

fix = "";
vuln = 0;

if (ver =~ "^2\.5([^0-9]|$)")
{
  fix = "2.5.8";
  vuln = ver_compare(ver:ver, fix:fix, strict:FALSE);
}
else if (ver =~ "^2\.6([^0-9]|$)")
{
  fix = "2.6.8";
  vuln = ver_compare(ver:ver, fix:fix, strict:FALSE);
}
else if (ver =~ "^2\.7([^0-9]|$)")
{
  fix = "2.7.12";
  vuln = ver_compare(ver:ver, fix:fix, strict:FALSE);
}

if (vuln >= 0) audit(AUDIT_WEB_APP_NOT_AFFECTED, app, url, ver);

# Report our findings.
report = NULL;
if (report_verbosity > 0)
{
  report =
    '\n  URL               : ' + url +
    '\n  Installed version : ' + ver +
    '\n  Fixed version     : ' + fix +
    '\n';
}

security_hole(port:port, extra:report);
