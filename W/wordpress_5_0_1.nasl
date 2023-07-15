#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(119615);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/04/27");

  script_cve_id(
    "CVE-2018-20147",
    "CVE-2018-20148",
    "CVE-2018-20149",
    "CVE-2018-20150",
    "CVE-2018-20151",
    "CVE-2018-20152",
    "CVE-2018-20153"
  );

  script_name(english:"WordPress < 4.9.9 / 5.x < 5.0.1 Multiple Vulnerabilities");
  script_summary(english:"Checks the version of WordPress.");

  script_set_attribute(attribute:"synopsis", value:
"A PHP application running on the remote web server is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the WordPress
application running on the remote web server is prior to 4.9.9, or
5.x prior to 5.0.1. It is, therefore, affected by multiple
vulnerabilities, including cross-site scripting (XSS) vulnerabilities
due to improper validation of user-supplied input before returning
it to users.");
  # https://wordpress.org/news/2018/12/wordpress-5-0-1-security-release/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b90fd4fc");
  script_set_attribute(attribute:"solution", value:
"Upgrade to WordPress version 4.9.9 or 5.0.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-20148");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/12/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/12/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/12/13");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:wordpress:wordpress");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2018-2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

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

# Per https://wordpress.org/download/release-archive/
# only 5.x is currently supported :
# "None of these are safe to use, except the latest in the 5.0 series, which is actively maintained."
constraints = [
  { "fixed_version":"3.7.28", "fixed_display" : "3.7.28 / 5.0.1" },
  { "min_version":"3.8", "fixed_version":"3.8.28", "fixed_display" : "3.8.28 / 5.0.1" },
  { "min_version":"3.9", "fixed_version":"3.9.26", "fixed_display" : "3.9.26 / 5.0.1" },
  { "min_version":"4.0", "fixed_version":"4.0.25", "fixed_display" : "4.0.25 / 5.0.1" },
  { "min_version":"4.1", "fixed_version":"4.1.25", "fixed_display" : "4.1.25 / 5.0.1" },
  { "min_version":"4.2", "fixed_version":"4.2.22", "fixed_display" : "4.2.22 / 5.0.1" },
  { "min_version":"4.3", "fixed_version":"4.3.18", "fixed_display" : "4.3.18 / 5.0.1" },
  { "min_version":"4.4", "fixed_version":"4.4.17", "fixed_display" : "4.4.17 / 5.0.1" },
  { "min_version":"4.5", "fixed_version":"4.5.16", "fixed_display" : "4.5.16 / 5.0.1" },
  { "min_version":"4.6", "fixed_version":"4.6.13", "fixed_display" : "4.6.13 / 5.0.1" },
  { "min_version":"4.7", "fixed_version":"4.7.12", "fixed_display" : "4.7.12 / 5.0.1" },
  { "min_version":"4.8", "fixed_version":"4.8.8", "fixed_display" : "4.8.8 / 5.0.1" },
  { "min_version":"4.9", "fixed_version":"4.9.9", "fixed_display" : "4.9.9 / 5.0.1" },
  { "min_version":"5.0", "fixed_version":"5.0.1", "fixed_display" : "5.0.1" }
];

vcf::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_HOLE,
  flags:{xss:TRUE}
);
