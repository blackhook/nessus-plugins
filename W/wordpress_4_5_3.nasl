#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(91810);
  script_version("1.8");
  script_cvs_date("Date: 2019/11/14");

  script_cve_id(
    "CVE-2016-5832",
    "CVE-2016-5833",
    "CVE-2016-5834",
    "CVE-2016-5835",
    "CVE-2016-5836",
    "CVE-2016-5837",
    "CVE-2016-5838",
    "CVE-2016-5839"
  );
  script_bugtraq_id(
    91362,
    91363,
    91364,
    91365,
    91366,
    91367,
    91368
  );

  script_name(english:"WordPress < 4.5.3 Multiple Vulnerabilities");
  script_summary(english:"Checks the version of WordPress.");

  script_set_attribute(attribute:"synopsis", value:
"A PHP application running on the remote web server is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the WordPress
application running on the remote web server is prior to 4.5.3.
It is, therefore, affected by the following vulnerabilities :

  - An unspecified flaw exists in the Customizer component
    that allows an unauthenticated, remote attacker to
    perform a redirect bypass.

  - Multiple cross-site scripting vulnerabilities exist due
    to improper validation of user-supplied input when
    handling attachment names. An unauthenticated, remote
    attacker can exploit these issues, via a specially
    crafted request, to execute arbitrary script code in a
    user's browser session.

  - An information disclosure vulnerability exists that
    allows an unauthenticated, remote attacker to disclose
    revision history.

  - An unspecified flaw exists in oEmbed that allows an
    unauthenticated, remote attacker to cause a denial of
    service condition.

  - An unspecified flaw exists that allows an
    unauthenticated, remote attacker to remove categories
    from posts.

  - An unspecified flaw exists that is triggered when
    handling stolen cookies. An unauthenticated, remote
    attacker can exploit this to change user passwords.

  - Multiple unspecified flaws exist in the
    sanitize_file_name() function that allow an
    unauthenticated, remote attacker to have an unspecified
    impact.

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"https://wordpress.org/news/2016/06/wordpress-4-5-3/");
  script_set_attribute(attribute:"solution", value:
"Upgrade to WordPress version 4.5.3 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2016-5839");

  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/06/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/06/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/06/24");

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
  { "fixed_version":"3.7.15", "fixed_display" : "3.7.15 / 4.5.3" },
  { "min_version":"3.8", "fixed_version":"3.8.15", "fixed_display" : "3.8.15 / 4.5.3" },
  { "min_version":"3.9", "fixed_version":"3.9.13", "fixed_display" : "3.9.13 / 4.5.3" },
  { "min_version":"4.0", "fixed_version":"4.0.12", "fixed_display" : "4.0.12 / 4.5.3" },
  { "min_version":"4.1", "fixed_version":"4.1.12", "fixed_display" : "4.1.12 / 4.5.3" },
  { "min_version":"4.2", "fixed_version":"4.2.9", "fixed_display" : "4.2.9 / 4.5.3" },
  { "min_version":"4.3", "fixed_version":"4.3.5", "fixed_display" : "4.3.5 / 4.5.3" },
  { "min_version":"4.4", "fixed_version":"4.4.4", "fixed_display" : "4.4.4 / 4.5.3" },
  { "min_version":"4.5", "fixed_version":"4.5.3", "fixed_display" : "4.5.3" }
];

vcf::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_WARNING,
  flags:{xss:TRUE}
);
