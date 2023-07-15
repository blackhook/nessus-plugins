#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(106622);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2010-1164", "CVE-2010-1165");
  script_bugtraq_id(39485);

  script_name(english:"Atlassian Jira < 4.1.1 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server hosts a web application that is potentially
affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the version of
Atlassian JIRA hosted on the remote web server is prior to
4.1.1. It is, therefore, potentially affected by multiple
vulnerabilities :

  - Remote authenticated attackers can exploit the
    privilege-escalation issue to gain SYSTEM-level privileges,
    completely compromising affected computers.

  - Remote attackers can leverage the cross-site scripting
    vulnerabilities to execute arbitrary script code in the
    browser of an unsuspecting user in the context of the
    affected site. This may allow the attacker to steal
    cookie-based authentication credentials and to launch
    other attacks.

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"https://blogs.apache.org/infra/entry/apache_org_04_09_2010");
  # https://confluence.atlassian.com/jira/jira-security-advisory-2010-04-16-216433270.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?7437b837");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant patch referenced in the JIRA security advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/04/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/04/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/02/06");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:atlassian:jira");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2018-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("jira_detect.nasl");
  script_require_keys("installed_sw/Atlassian JIRA", "Settings/ParanoidReport");
  script_require_ports("Services/www", 8080);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("install_func.inc");

if (report_paranoia < 2)
{
  audit(AUDIT_PARANOID);
}

app = "Atlassian JIRA";
get_install_count(app_name:app, exit_if_zero:TRUE);
port = get_http_port(default:8080);
install = get_single_install(app_name:app, port:port, exit_if_unknown_ver:TRUE);

dir = install['path'];
ver = install['version'];
url = build_url(port:port, qs:dir);

fix = "4.1.1";
if (ver_compare(ver:ver, fix:fix, strict:FALSE) >= 0)
{
  audit(AUDIT_WEB_APP_NOT_AFFECTED, app, url, ver);
}

report =
  '\n  URL               : ' + url +
  '\n  Installed version : ' + ver +
  '\n  Fixed version     : ' + fix +
  '\n';
security_report_v4(severity:SECURITY_HOLE, port:port, extra:report, xss:TRUE);
exit(0);
