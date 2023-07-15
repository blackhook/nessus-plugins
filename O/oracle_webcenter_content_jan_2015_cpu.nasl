#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(81605);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2015-0376");
  script_bugtraq_id(72189);

  script_name(english:"Oracle WebCenter Content Server Remote Security Vulnerability (January 2015 CPU)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by an unspecified remote security
vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Oracle WebCenter Content installed on the remote host
is potentially affected by an unspecified remote security
vulnerability in the Content Server component.");
  # https://www.oracle.com/technetwork/topics/security/cpujan2015-1972971.html#AppendixFMW
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?cbcd77c1");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the January 2015 Oracle
Critical Patch Update advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");

  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/01/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/01/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/03/04");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:fusion_middleware");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2015-2022 Tenable Network Security, Inc.");

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

matches = eregmatch(string:version, pattern:"([0-9.]+) \(([0-9.]+)\)");
if (isnull(matches)) audit(AUDIT_VER_FORMAT, version);
main_ver = matches[1];
sub_ver = matches[2];

report = '';

if (main_ver == "11.1.1.8.0")
{
  # Patch 20022599
  # 11.1.1.8.0PSU-2015-01-08 07:49:21Z-r123144
  # 11.1.1.8.9 (123144)
  fixed_build = 123144;
  build = int(sub_ver);
  if (build < fixed_build)
  {
    report = '\n  Installed version : ' + main_ver + ' (' + sub_ver + ')' +
             '\n  Fixed version     : 11.1.1.8.0 (123144)' +
             '\n  Required patch    : 20022599\n';
  }
}

if (report == '') audit(AUDIT_WEB_APP_NOT_AFFECTED, appname, install_url, version);

if (report_verbosity > 0) security_warning(extra:report, port:port);
else security_warning(port);
