#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

# The descriptive text and package checks in this plugin were
# extracted from WordPress Security Advisory wordpress-6-0-2-security-and-maintenance-release.

include('compat.inc');

if (description)
{
  script_id(164521);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/08/31");

  script_name(english:"WordPress 6.0 < 6.0.2 / 5.9 < 5.9.4 / 5.8 < 5.8.5 / 5.7 < 5.7.7 / 5.6 < 5.6.9 / 5.5 < 5.5.10 / 5.4 < 5.4.11 / 5.3 < 5.3.13 / 5.2 < 5.2.16 / 5.1 < 5.1.14 / 5.0 < 5.0.17 / 4.9 < 4.9.21 / 4.8 < 4.8.20 / 4.7 < 4.7.24 / 4.6 < 4.6.24 / 4.5 < 4.5.27 / 4.4 < 4.4.28 / 4.3 < 4.3.29 / 4.2 < 4.2.33 / 4.1 < 4.1.36 / 4.0 < 4.0.36 / 3.9 < 3.9.37 / 3.8 < 3.8.39 / 3.7 < 3.7.39");

  script_set_attribute(attribute:"synopsis", value:
"A PHP application running on the remote web server is affected by one or more vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"WordPress versions 6.0 < 6.0.2 / 5.9 < 5.9.4 / 5.8 < 5.8.5 / 5.7 < 5.7.7 / 5.6 < 5.6.9 / 5.5 < 5.5.10 / 5.4 < 5.4.11 /
5.3 < 5.3.13 / 5.2 < 5.2.16 / 5.1 < 5.1.14 / 5.0 < 5.0.17 / 4.9 < 4.9.21 / 4.8 < 4.8.20 / 4.7 < 4.7.24 / 4.6 < 4.6.24 /
4.5 < 4.5.27 / 4.4 < 4.4.28 / 4.3 < 4.3.29 / 4.2 < 4.2.33 / 4.1 < 4.1.36 / 4.0 < 4.0.36 / 3.9 < 3.9.37 / 3.8 < 3.8.39 /
3.7 < 3.7.39 are affected by one or more vulnerabilities");
  script_set_attribute(attribute:"see_also", value:"https://wordpress.org/download/releases/");
  # https://wordpress.org/news/2022/08/wordpress-6-0-2-security-and-maintenance-release/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?269ca1ac");
  # https://make.wordpress.org/core/2022/08/23/wordpress-6-0-2-rc1-is-now-available/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?9c98ed6f");
  script_set_attribute(attribute:"see_also", value:"https://wordpress.org/support/wordpress-version/version-6-0-2");
  script_set_attribute(attribute:"solution", value:
"Upgrade to WordPress version 6.0.2, 5.9.4, 5.8.5, 5.7.7, 5.6.9, 5.5.10, 5.4.11, 5.3.13, 5.2.16, 5.1.14, 5.0.17, 4.9.21,
4.8.20, 4.7.24, 4.6.24, 4.5.27, 4.4.28, 4.3.29, 4.2.33, 4.1.36, 4.0.36, 3.9.37, 3.8.39, 3.7.39 or later.");
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/08/30");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/08/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/08/31");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:wordpress:wordpress");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("wordpress_detect.nasl");
  script_require_keys("www/PHP", "installed_sw/WordPress", "Settings/ParanoidReport");
  script_require_ports("Services/www", 80, 443);

  exit(0);
}

include('vcf.inc');
include('http.inc');

var app = 'WordPress';
get_install_count(app_name:app, exit_if_zero:TRUE);

if (report_paranoia < 2) audit(AUDIT_PARANOID);

var port = get_http_port(default:80, php:TRUE);

var app_info = vcf::get_app_info(app:'WordPress', port:port, webapp:TRUE);

var constraints = [
  { 'min_version' : '3.7', 'fixed_version' : '3.7.39' },
  { 'min_version' : '3.8', 'fixed_version' : '3.8.39' },
  { 'min_version' : '3.9', 'fixed_version' : '3.9.37' },
  { 'min_version' : '4.0', 'fixed_version' : '4.0.36' },
  { 'min_version' : '4.1', 'fixed_version' : '4.1.36' },
  { 'min_version' : '4.2', 'fixed_version' : '4.2.33' },
  { 'min_version' : '4.3', 'fixed_version' : '4.3.29' },
  { 'min_version' : '4.4', 'fixed_version' : '4.4.28' },
  { 'min_version' : '4.5', 'fixed_version' : '4.5.27' },
  { 'min_version' : '4.6', 'fixed_version' : '4.6.24' },
  { 'min_version' : '4.7', 'fixed_version' : '4.7.24' },
  { 'min_version' : '4.8', 'fixed_version' : '4.8.20' },
  { 'min_version' : '4.9', 'fixed_version' : '4.9.21' },
  { 'min_version' : '5.0', 'fixed_version' : '5.0.17' },
  { 'min_version' : '5.1', 'fixed_version' : '5.1.14' },
  { 'min_version' : '5.2', 'fixed_version' : '5.2.16' },
  { 'min_version' : '5.3', 'fixed_version' : '5.3.13' },
  { 'min_version' : '5.4', 'fixed_version' : '5.4.11' },
  { 'min_version' : '5.5', 'fixed_version' : '5.5.10' },
  { 'min_version' : '5.6', 'fixed_version' : '5.6.9' },
  { 'min_version' : '5.7', 'fixed_version' : '5.7.7' },
  { 'min_version' : '5.8', 'fixed_version' : '5.8.5' },
  { 'min_version' : '5.9', 'fixed_version' : '5.9.4' },
  { 'min_version' : '6.0', 'fixed_version' : '6.0.2' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
