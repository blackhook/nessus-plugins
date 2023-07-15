#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(110722);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2018-12613");
  script_bugtraq_id(104532);

  script_name(english:"phpMyAdmin 4.8.x < 4.8.2 Vulnerability (PMASA-2018-4)");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server hosts a PHP application that is affected by
file inclusion and remote code execution vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the phpMyAdmin
application hosted on the remote web server is 4.8.x prior to
4.8.2. It is, therefore, affected by the file inclusion and 
remote code execution vulnerabilities

Note that Nessus has not attempted to exploit these issues but has
instead relied only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"https://www.phpmyadmin.net/security/PMASA-2018-4/");
  script_set_attribute(attribute:"solution", value:
"Upgrade to phpMyAdmin version 4.8.2 or later.
Alternatively, apply the patch referenced in the vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-12613");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"d2_elliot_name", value:"phpMyAdmin 4.8.1 RCE");
  script_set_attribute(attribute:"exploit_framework_d2_elliot", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'phpMyAdmin Authenticated Remote Code Execution');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/06/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/06/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/06/27");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:phpmyadmin:phpmyadmin");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2018-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("phpMyAdmin_detect.nasl");
  script_require_keys("www/PHP", "installed_sw/phpMyAdmin", "Settings/ParanoidReport");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("install_func.inc");

if (report_paranoia < 2) audit(AUDIT_PARANOID);

appname = "phpMyAdmin";
get_install_count(app_name:appname, exit_if_zero:TRUE);

port = get_http_port(default:80, php:TRUE);
install = get_single_install(app_name:appname, port:port, exit_if_unknown_ver:TRUE);
dir = install['path'];
url = build_url(qs:dir, port:port);
version = install['version'];

if (version =~ "^4(\.8)?$") audit(AUDIT_VER_NOT_GRANULAR, appname, port, version);
if (version !~ "^4\.8\.[0-9]") audit(AUDIT_WEB_APP_NOT_INST, appname + " 4.8.x", port);

re = make_array(
  -2, "-beta(\d+)",
  -1, "-rc(\d+)"
);

# Affected version
# 4.8.x < 4.8.2
cut_off   = '4.8.0';
fixed_ver = '4.8.2';
if (ver_compare(ver:version, minver:cut_off, fix:fixed_ver, regexes:re) == -1)
{
  report =
    '\n  URL               : ' + url +
    '\n  Installed version : ' + version +
    '\n  Fixed version     : ' + fixed_ver +
    '\n';

  security_report_v4(port:port, severity:SECURITY_WARNING, extra:report);
}

else audit(AUDIT_WEB_APP_NOT_AFFECTED, appname, url, version);
