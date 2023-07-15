#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(105004);
  script_version("1.11");
  script_cvs_date("Date: 2019/03/29  9:51:59");

  script_cve_id(
    "CVE-2017-17091",
    "CVE-2017-17092",
    "CVE-2017-17093",
    "CVE-2017-17094"
  );
  script_bugtraq_id(102024);

  script_name(english:"WordPress < 4.9.1 Multiple Vulnerabilities");
  script_summary(english:"Checks the version of WordPress.");

  script_set_attribute(attribute:"synopsis", value:
"A PHP application running on the remote web server is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the WordPress
application running on the remote web server is prior to 4.9.1.
It is, therefore, affected by multiple vulnerabilities.");
  #https://wordpress.org/news/2017/11/wordpress-4-9-1-security-and-maintenance-release/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?383c32fd");
  script_set_attribute(attribute:"solution", value:
"Upgrade to WordPress version 4.9.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-17091");
  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/11/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/11/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/12/04");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:wordpress:wordpress");
  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2017-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("wordpress_detect.nasl");
  script_require_keys("www/PHP", "installed_sw/WordPress", "Settings/ParanoidReport");
  script_require_ports("Services/www", 80, 443);

  exit(0);
}

include("vcf.inc");
include("http.inc");

if (report_paranoia < 2) audit(AUDIT_PARANOID);

app = "WordPress";
port = get_http_port(default:80, php:TRUE);

app_info = vcf::get_app_info(app:app, port:port, webapp:TRUE);
vcf::check_granularity(app_info:app_info, sig_segments:2);

constraints = [
  { "min_version":"1.5", "fixed_version":"3.7.24", "fixed_display" : "3.7.24 / 4.9.1" },
  { "min_version":"3.8", "fixed_version":"3.8.24", "fixed_display" : "3.8.24 / 4.9.1" },
  { "min_version":"3.9", "fixed_version":"3.9.22", "fixed_display" : "3.9.22 / 4.9.1" },
  { "min_version":"4.0", "fixed_version":"4.0.21", "fixed_display" : "4.0.21 / 4.9.1" },
  { "min_version":"4.1", "fixed_version":"4.1.21", "fixed_display" : "4.1.21 / 4.9.1" },
  { "min_version":"4.2", "fixed_version":"4.2.18", "fixed_display" : "4.2.18 / 4.9.1" },
  { "min_version":"4.3", "fixed_version":"4.3.14", "fixed_display" : "4.3.14 / 4.9.1" },
  { "min_version":"4.4", "fixed_version":"4.4.13", "fixed_display" : "4.4.13 / 4.9.1" },
  { "min_version":"4.5", "fixed_version":"4.5.12", "fixed_display" : "4.5.12 / 4.9.1" },
  { "min_version":"4.6", "fixed_version":"4.6.9", "fixed_display" : "4.6.9 / 4.9.1" },
  { "min_version":"4.7", "fixed_version":"4.7.8", "fixed_display" : "4.7.8 / 4.9.1" },
  { "min_version":"4.8", "fixed_version":"4.8.4", "fixed_display" : "4.8.4 / 4.9.1" },
  { "min_version":"4.9", "fixed_version":"4.9.1", "fixed_display" : "4.9.1" }
];

vcf::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_WARNING
);
