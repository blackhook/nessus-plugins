#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(93516);
  script_version("1.10");
  script_cvs_date("Date: 2019/04/01  9:30:05");

  script_cve_id("CVE-2016-7168", "CVE-2016-7169");

  script_name(english:"WordPress < 4.6.1 Multiple Vulnerabilities");
  script_summary(english:"Checks the version of WordPress.");

  script_set_attribute(attribute:"synopsis", value:
"A PHP application running on the remote web server is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the WordPress
application running on the remote web server is prior to 4.6.1.
It is, therefore, affected by multiple vulnerabilities :

  - A cross-site scripting vulnerability (XSS) exists when
    handling file names of uploaded images due to improper
    validation of input before returning it to users. An
    authenticated, remote attacker can exploit this, via a
    specially crafted request, to execute arbitrary script
    code in a user's browser session. (CVE-2016-7168)

  - A path traversal vulnerability exists in the WordPress
    upgrade package uploader due to improper sanitization of
    user-supplied input. An authenticated, remote attacker
    can exploit this, via a specially crafted request, to
    impact confidentiality, integrity, and availability.
    (CVE-2016-7169)

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  # https://wordpress.org/news/2016/09/wordpress-4-6-1-security-and-maintenance-release/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?be1e697e");
  script_set_attribute(attribute:"see_also", value:"https://codex.wordpress.org/Version_4.6.1");
  script_set_attribute(attribute:"see_also", value:"https://core.trac.wordpress.org/query?milestone=4.6.1");
  # https://sumofpwn.nl/advisory/2016/persistent_cross_site_scripting_vulnerability_in_wordpress_due_to_unsafe_processing_of_file_names.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0366a41c");
  script_set_attribute(attribute:"solution", value:
"Upgrade to WordPress version 4.6.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2016-7169");
  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/09/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/09/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/09/15");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:wordpress:wordpress");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2016-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
  { "min_version":"2.5", "fixed_version":"3.7.16", "fixed_display" : "3.7.16 / 4.6.1" },
  { "min_version":"3.8", "fixed_version":"3.8.16", "fixed_display" : "3.8.16 / 4.6.1" },
  { "min_version":"3.9", "fixed_version":"3.9.14", "fixed_display" : "3.9.14 / 4.6.1" },
  { "min_version":"4.0", "fixed_version":"4.0.13", "fixed_display" : "4.0.13 / 4.6.1" },
  { "min_version":"4.1", "fixed_version":"4.1.13", "fixed_display" : "4.1.13 / 4.6.1" },
  { "min_version":"4.2", "fixed_version":"4.2.10", "fixed_display" : "4.2.10 / 4.6.1" },
  { "min_version":"4.3", "fixed_version":"4.3.6", "fixed_display" : "4.3.6 / 4.6.1" },
  { "min_version":"4.4", "fixed_version":"4.4.5", "fixed_display" : "4.4.5 / 4.6.1" },
  { "min_version":"4.5", "fixed_version":"4.5.4", "fixed_display" : "4.5.4 / 4.6.1" },
  { "min_version":"4.6", "fixed_version":"4.6.1", "fixed_display" : "4.6.1" }
];

vcf::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_WARNING,
  flags:{xss:TRUE}
);
