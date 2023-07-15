#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(107090);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2018-2564", "CVE-2018-2596", "CVE-2018-2716");
  script_bugtraq_id(102541, 102545, 102672);

  script_name(english:"Oracle WebCenter Content Multiple Vulnerabilities (January 2018 CPU)");

  script_set_attribute(attribute:"synopsis", value:
"An application running on the remote host is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Oracle WebCenter Content running on the remote host is
affected by multiple vulnerabilities.");
  # https://www.oracle.com/technetwork/security-advisory/cpujan2018-3236628.html#AppendixFMW
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?6072c657");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the January 2018 Oracle
Critical Patch Update advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");

  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/01/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/01/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/03/01");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:fusion_middleware");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2018-2022 Tenable Network Security, Inc.");

  script_dependencies("oracle_webcenter_content_detect.nasl");
  script_require_keys("installed_sw/Oracle WebCenter Content", "Settings/ParanoidReport");
  script_exclude_keys("Settings/disable_cgi_scanning");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

appname = "Oracle WebCenter Content";

if (report_paranoia < 2) audit(AUDIT_PARANOID);

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

if (main_ver == "12.2.1.3.0")
{
  # Patch 27042584
  # 12.2.1.3.0 (158565)
  fixed_build = 158565;;
  patch = 27042584;
}
else if (main_ver == "12.2.1.2.0")
{
  # Patch 27116621
  # 12.2.1.2.0 (158156)
  fixed_build = 158156;
  patch = 27116621;
}
else if (main_ver == "11.1.1.9.0")
{
  # Patch 27042562
  # 11.1.1.9.0 (171120)
  fixed_build = 171120;
  patch = 27042562;
}
if (build < fixed_build)
{
  report = '\n  Installed version : ' + main_ver + ' (' + sub_ver + ')' +
           '\n  Fixed version     : ' + main_ver + ' (' + fixed_build + ')' +
           '\n  Required patch    : ' + patch + '\n';
}

if (report == '') audit(AUDIT_WEB_APP_NOT_AFFECTED, appname, install_url, version);
else security_report_v4(port:port, extra:report, severity:SECURITY_WARNING);
