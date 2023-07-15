#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(88579);
  script_version("1.13");
  script_cvs_date("Date: 2019/11/19");

  script_cve_id("CVE-2016-2221", "CVE-2016-2222");
  script_bugtraq_id(82454, 82463);

  script_name(english:"WordPress < 4.4.2 Multiple Vulnerabilities");
  script_summary(english:"Checks the version of WordPress.");

  script_set_attribute(attribute:"synopsis", value:
"The PHP application running on the remote web server is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the WordPress
application running on the remote web server is prior to 4.4.2.
It is, therefore, affected by the following vulnerabilities :

  - A cross-site redirection vulnerability exists due to a
    failure by the application to validate certain input.
    An unauthenticated, remote attacker can exploit this,
    via a specially crafted link, to redirect a victim from
    a legitimate web site to an arbitrary web site of the
    attacker's choosing, thus allowing further attacks on
    client-side software, such as web browsers or document
    rendering software. (CVE-2016-2221)

  - A server-side request forgery vulnerability exists in
    which the server can be induced into performing
    unintended actions when handling certain requests. An
    unauthenticated, remote attacker can exploit this, via
    crafted requests to certain local URIs, to conduct
    further host-based attacks, such as bypassing access
    restrictions, conducting port scanning, enumerating
    internal networks and hosts, or invoking additional
    protocols. (CVE-2016-2222)

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"https://wpvulndb.com/vulnerabilities/8376");
  script_set_attribute(attribute:"see_also", value:"https://wpvulndb.com/vulnerabilities/8377");
  # https://wordpress.org/news/2016/02/wordpress-4-4-2-security-and-maintenance-release/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d40090f8");
  script_set_attribute(attribute:"see_also", value:"https://codex.wordpress.org/Version_4.4.2");
  script_set_attribute(attribute:"solution", value:
"Upgrade to WordPress version 4.4.2 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:N/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2016-2221");

  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/02/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/02/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/02/04");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:wordpress:wordpress");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2016-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("wordpress_detect.nasl");
  script_require_keys("www/PHP", "installed_sw/WordPress", "Settings/ParanoidReport");
  script_require_ports("Services/www", 80);

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
  { "min_version":"3.7", "fixed_version":"3.7.13", "fixed_display" : "3.7.13 / 4.4.2" },
  { "min_version":"3.8", "fixed_version":"3.8.13", "fixed_display" : "3.8.13 / 4.4.2" },
  { "min_version":"3.9", "fixed_version":"3.9.11", "fixed_display" : "3.9.11 / 4.4.2" },
  { "min_version":"4.0", "fixed_version":"4.0.10", "fixed_display" : "4.0.10 / 4.4.2" },
  { "min_version":"4.1", "fixed_version":"4.1.10", "fixed_display" : "4.1.10 / 4.4.2" },
  { "min_version":"4.2", "fixed_version":"4.2.7", "fixed_display" : "4.2.7 / 4.4.2" },
  { "min_version":"4.3", "fixed_version":"4.3.3", "fixed_display" : "4.3.3 / 4.4.2" },
  { "min_version":"4.4", "fixed_version":"4.4.2", "fixed_display" : "4.4.2" }
];

vcf::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_WARNING
);
