#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

# The descriptive text and package checks in this plugin were
# extracted from WordPress Security Advisory wordpress-5-8-3-security-release.

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(156546);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/11/21");

  script_cve_id(
    "CVE-2022-21661",
    "CVE-2022-21662",
    "CVE-2022-21663",
    "CVE-2022-21664"
  );
  script_xref(name:"IAVA", value:"2022-A-0003-S");

  script_name(english:"WordPress 5.8 < 5.8.3 / 5.7 < 5.7.5 / 5.6 < 5.6.7 / 5.5 < 5.5.8 / 5.4 < 5.4.9 / 5.3 < 5.3.11 / 5.2 < 5.2.14 / 5.1 < 5.1.12 / 5.0 < 5.0.15 / 4.9 < 4.9.19 / 4.8 < 4.8.18 / 4.7 < 4.7.22 / 4.6 < 4.6.22 / 4.5 < 4.5.25 / 4.4 < 4.4.26 / 4.3 < 4.3.27 / 4.2 < 4.2.31 / 4.1 < 4.1.34 / 4.0 < 4.0.34 / 3.9 < 3.9.35 / 3.8 < 3.8.37 / 3.7 < 3.7.37");

  script_set_attribute(attribute:"synopsis", value:
"A PHP application running on the remote web server is affected by one or more vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"WordPress versions 5.8 < 5.8.3 / 5.7 < 5.7.5 / 5.6 < 5.6.7 / 5.5 < 5.5.8 / 5.4 < 5.4.9 / 5.3 < 5.3.11 / 5.2 < 5.2.14 /
5.1 < 5.1.12 / 5.0 < 5.0.15 / 4.9 < 4.9.19 / 4.8 < 4.8.18 / 4.7 < 4.7.22 / 4.6 < 4.6.22 / 4.5 < 4.5.25 / 4.4 < 4.4.26 /
4.3 < 4.3.27 / 4.2 < 4.2.31 / 4.1 < 4.1.34 / 4.0 < 4.0.34 / 3.9 < 3.9.35 / 3.8 < 3.8.37 / 3.7 < 3.7.37 are affected by
one or more vulnerabilities");
  script_set_attribute(attribute:"see_also", value:"https://wordpress.org/download/releases/");
  script_set_attribute(attribute:"see_also", value:"https://wordpress.org/news/2022/01/wordpress-5-8-3-security-release/");
  script_set_attribute(attribute:"see_also", value:"https://wordpress.org/support/wordpress-version/version-5-8-3/");
  script_set_attribute(attribute:"solution", value:
"Upgrade to WordPress version 5.8.3, 5.7.5, 5.6.7, 5.5.8, 5.4.9, 5.3.11, 5.2.14, 5.1.12, 5.0.15, 4.9.19, 4.8.18, 4.7.22,
4.6.22, 4.5.25, 4.4.26, 4.3.27, 4.2.31, 4.1.34, 4.0.34, 3.9.35, 3.8.37, 3.7.37 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-21664");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/01/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/01/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/01/06");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:wordpress:wordpress");
  script_set_attribute(attribute:"stig_severity", value:"I");
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
  { 'min_version' : '3.7', 'fixed_version' : '3.7.37' },
  { 'min_version' : '3.8', 'fixed_version' : '3.8.37' },
  { 'min_version' : '3.9', 'fixed_version' : '3.9.35' },
  { 'min_version' : '4.0', 'fixed_version' : '4.0.34' },
  { 'min_version' : '4.1', 'fixed_version' : '4.1.34' },
  { 'min_version' : '4.2', 'fixed_version' : '4.2.31' },
  { 'min_version' : '4.3', 'fixed_version' : '4.3.27' },
  { 'min_version' : '4.4', 'fixed_version' : '4.4.26' },
  { 'min_version' : '4.5', 'fixed_version' : '4.5.25' },
  { 'min_version' : '4.6', 'fixed_version' : '4.6.22' },
  { 'min_version' : '4.7', 'fixed_version' : '4.7.22' },
  { 'min_version' : '4.8', 'fixed_version' : '4.8.18' },
  { 'min_version' : '4.9', 'fixed_version' : '4.9.19' },
  { 'min_version' : '5.0', 'fixed_version' : '5.0.15' },
  { 'min_version' : '5.1', 'fixed_version' : '5.1.12' },
  { 'min_version' : '5.2', 'fixed_version' : '5.2.14' },
  { 'min_version' : '5.3', 'fixed_version' : '5.3.11' },
  { 'min_version' : '5.4', 'fixed_version' : '5.4.9' },
  { 'min_version' : '5.5', 'fixed_version' : '5.5.8' },
  { 'min_version' : '5.6', 'fixed_version' : '5.6.7' },
  { 'min_version' : '5.7', 'fixed_version' : '5.7.5' },
  { 'min_version' : '5.8', 'fixed_version' : '5.8.3' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
