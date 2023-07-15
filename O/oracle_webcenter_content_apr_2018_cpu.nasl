#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(136809);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2018-2828");
  script_bugtraq_id(103797);

  script_name(english:"Oracle WebCenter Content Unspecified Vulnerability (April 2018 CPU)");

  script_set_attribute(attribute:"synopsis", value:
"An application running on the remote host is affected by
an unspecified vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Oracle WebCenter Content running on the remote host is affected by a vulnerability in the Oracle
WebCenter Content component of Oracle Fusion Middleware (subcomponent: Content Server). Supported versions that are
affected are 11.1.1.9.0, 12.2.1.2.0 and 12.2.1.3.0. An easy to exploit vulnerability allows a low privileged attacker
with network access via HTTP to compromise Oracle WebCenter Content. A successful attack requires human interaction from
a person other than the attacker and while the vulnerability is in Oracle WebCenter Content, attacks may significantly
impact additional products. Successful attacks of this vulnerability can result in unauthorized access to critical data
or complete access to all Oracle WebCenter Content accessible data as well as unauthorized update, insert or delete
access to some of Oracle WebCenter Content accessible data and unauthorized ability to cause a partial denial of service
(partial DOS) of Oracle WebCenter Content.");
  # http://www.oracle.com/technetwork/security-advisory/cpuapr2018-3678067.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?76507bf8");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the April 2018 Oracle Critical Patch Update advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:R/S:C/C:H/I:L/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-2828");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/04/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/04/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/05/22");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:fusion_middleware");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2020-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("oracle_webcenter_content_detect.nasl");
  script_require_keys("installed_sw/Oracle WebCenter Content");
  script_exclude_keys("Settings/disable_cgi_scanning");

  exit(0);
}

include('http.inc');
include('webapp_func.inc');
include('install_func.inc');

appname = 'Oracle WebCenter Content';

get_install_count(app_name:appname, exit_if_zero:TRUE);

port = get_http_port(default:80);

install = get_single_install(app_name:appname, port:port, exit_if_unknown_ver:TRUE);

version = install['version'];
dir = install['path'];

install_url = build_url(port: port, qs:dir);

matches = pregmatch(string:version, pattern:"([0-9.]+) \(([0-9.]+)\)");
if (empty_or_null(matches)) audit(AUDIT_VER_FORMAT, version);
main_ver = matches[1];
sub_ver = matches[2];
build = int(sub_ver);
fixed_build = 0;

report = '';

if (main_ver == '12.2.1.3.0')
{
  # Patch 27393392
  # 12.2.1.3.0 (160174)
  fixed_build = 160174;
  patch = 27393392;
}
else if (main_ver == '12.2.1.2.0')
{
  # Patch 27393378
  # 12.2.1.2.0 (160414)
  fixed_build = 160414;
  patch = 27393378;
}
else if (main_ver == '11.1.1.9.0')
{
  # Patch 27393411
  # 11.1.1.9.0 (159813)
  fixed_build = 159813;
  patch = 27393411;
}
if (build < fixed_build)
{
  report = '\n  Installed version : ' + main_ver + ' (' + sub_ver + ')' +
           '\n  Fixed version     : ' + main_ver + ' (' + fixed_build + ')' +
           '\n  Required patch    : ' + patch + '\n';
}

if (report == '') audit(AUDIT_WEB_APP_NOT_AFFECTED, appname, install_url, version);
else security_report_v4(port:port, extra:report, severity:SECURITY_WARNING);
