#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(111229);
  script_version("1.5");
  script_cvs_date("Date: 2019/11/04");

  script_cve_id("CVE-2018-12895");

  script_name(english:"WordPress < 4.9.7 Arbitrary File Deletion Vulnerability");
  script_summary(english:"Checks the version of WordPress.");

  script_set_attribute(attribute:"synopsis", value:
"A PHP application running on the remote web server is affected by
an arbitrary file deletion vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the WordPress
application running on the remote web server is prior to 4.9.7. It is,
therefore, affected by an arbitrary file deletion vulnerability that
can lead to remote code execution.");
  # https://blog.ripstech.com/2018/wordpress-file-delete-to-code-execution/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?2a24cd03");
  # https://www.wordfence.com/blog/2018/07/details-of-an-additional-file-deletion-vulnerability-patched-in-wordpress-4-9-7/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?5478aed7");
  # https://wordpress.org/news/2018/07/wordpress-4-9-7-security-and-maintenance-release/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?44e0dfce");
  script_set_attribute(attribute:"solution", value:
"Upgrade to WordPress version 4.9.7 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-12895");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/07/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/07/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/07/24");

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

app = "WordPress";
port = get_http_port(default:80, php:TRUE);

app_info = vcf::get_app_info(app:app, port:port, webapp:TRUE);
vcf::check_granularity(app_info:app_info, sig_segments:2);

constraints = [
  { "fixed_version":"3.7.27", "fixed_display" : "3.7.27 / 4.9.7" },
  { "min_version":"3.8", "fixed_version":"3.8.27", "fixed_display" : "3.8.27 / 4.9.7" },
  { "min_version":"3.9", "fixed_version":"3.9.25", "fixed_display" : "3.9.25 / 4.9.7" },
  { "min_version":"4.0", "fixed_version":"4.0.24", "fixed_display" : "4.0.24 / 4.9.7" },
  { "min_version":"4.1", "fixed_version":"4.1.24", "fixed_display" : "4.1.24 / 4.9.7" },
  { "min_version":"4.2", "fixed_version":"4.2.21", "fixed_display" : "4.2.21 / 4.9.7" },
  { "min_version":"4.3", "fixed_version":"4.3.17", "fixed_display" : "4.3.17 / 4.9.7" },
  { "min_version":"4.4", "fixed_version":"4.4.16", "fixed_display" : "4.4.16 / 4.9.7" },
  { "min_version":"4.5", "fixed_version":"4.5.15", "fixed_display" : "4.5.15 / 4.9.7" },
  { "min_version":"4.6", "fixed_version":"4.6.12", "fixed_display" : "4.6.12 / 4.9.7" },
  { "min_version":"4.7", "fixed_version":"4.7.11", "fixed_display" : "4.7.11 / 4.9.7" },
  { "min_version":"4.8", "fixed_version":"4.8.7", "fixed_display" : "4.8.7 / 4.9.7" },
  { "min_version":"4.9", "fixed_version":"4.9.7", "fixed_display" : "4.9.7" }
];

vcf::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_WARNING
);
