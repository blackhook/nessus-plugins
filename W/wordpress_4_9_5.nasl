#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(109034);
  script_version("1.10");
  script_cvs_date("Date: 2019/11/08");

  script_cve_id("CVE-2018-6389", "CVE-2018-10102");

  script_name(english:"WordPress < 4.9.5 Multiple Vulnerabilities");
  script_summary(english:"Checks the version of WordPress.");

  script_set_attribute(attribute:"synopsis", value:
"A PHP application running on the remote web server is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the WordPress
application running on the remote web server is prior to 4.9.5. It is,
therefore, affected by multiple vulnerabilities.");
  # https://wordpress.org/news/2018/04/wordpress-4-9-5-security-and-maintenance-release/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?1f28948e");
  script_set_attribute(attribute:"solution", value:
"Upgrade to WordPress version 4.9.5 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-10102");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/04/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/04/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/04/13");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:wordpress:wordpress");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2018-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("wordpress_detect.nasl");
  script_require_keys("www/PHP", "installed_sw/WordPress", "Settings/ParanoidReport");
  script_require_ports("Services/www", 80, 443);

  exit(0);
}

include("vcf.inc");
include("http.inc");

if (report_paranoia < 2) audit(AUDIT_PARANOID);

if (report_paranoia < 2) audit(AUDIT_PARANOID);

app = "WordPress";
port = get_http_port(default:80, php:TRUE);

app_info = vcf::get_app_info(app:app, port:port, webapp:TRUE);
vcf::check_granularity(app_info:app_info, sig_segments:2);

constraints = [
  { "fixed_version":"3.7.26", "fixed_display" : "3.7.26 / 4.9.5" },
  { "min_version":"3.8", "fixed_version":"3.8.26", "fixed_display" : "3.8.26 / 4.9.5" },
  { "min_version":"3.9", "fixed_version":"3.9.24", "fixed_display" : "3.9.24 / 4.9.5" },
  { "min_version":"4.0", "fixed_version":"4.0.23", "fixed_display" : "4.0.23 / 4.9.5" },
  { "min_version":"4.1", "fixed_version":"4.1.23", "fixed_display" : "4.1.23 / 4.9.5" },
  { "min_version":"4.2", "fixed_version":"4.2.20", "fixed_display" : "4.2.20 / 4.9.5" },
  { "min_version":"4.3", "fixed_version":"4.3.16", "fixed_display" : "4.3.16 / 4.9.5" },
  { "min_version":"4.4", "fixed_version":"4.4.15", "fixed_display" : "4.4.15 / 4.9.5" },
  { "min_version":"4.5", "fixed_version":"4.5.14", "fixed_display" : "4.5.14 / 4.9.5" },
  { "min_version":"4.6", "fixed_version":"4.6.11", "fixed_display" : "4.6.11 / 4.9.5" },
  { "min_version":"4.7", "fixed_version":"4.7.10", "fixed_display" : "4.7.10 / 4.9.5" },
  { "min_version":"4.8", "fixed_version":"4.8.6", "fixed_display" : "4.8.6 / 4.9.5" },
  { "min_version":"4.9", "fixed_version":"4.9.5", "fixed_display" : "4.9.5" }
];

vcf::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_WARNING
);
