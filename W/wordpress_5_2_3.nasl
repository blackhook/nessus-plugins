#
# (C) Tenable Network Security, Inc.
#

# The descriptive text and package checks in this plugin were
# extracted from WordPress Security Advisory wordpress-5-2-3-security-and-maintenance-release.

include('compat.inc');

if (description)
{
  script_id(128554);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/29");

  script_cve_id(
    "CVE-2019-16217",
    "CVE-2019-16218",
    "CVE-2019-16219",
    "CVE-2019-16220",
    "CVE-2019-16221",
    "CVE-2019-16222",
    "CVE-2019-16223"
  );

  script_name(english:"WordPress <= 3.6.1 / 3.7.x < 3.7.30 / 3.8.x < 3.8.30 / 3.9.x < 3.9.28 / 4.0.x < 4.0.27 / 4.1.x < 4.1.27 / 4.2.x < 4.2.24 / 4.3.x < 4.3.20 / 4.4.x < 4.4.19 / 4.5.x < 4.5.18 / 4.6.x < 4.6.15 / 4.7.x < 4.7.14 / 4.8.x < 4.8.10 / 4.9.x < 4.9.11 / 5.0.x < 5.0.6 / 5.1.x < 5.1.2 / 5.2.x < 5.2.3 Multiple Vulnerabilities");
  script_summary(english:"Checks the version of WordPress.");

  script_set_attribute(attribute:"synopsis", value:
"Checks the version of WordPress.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the WordPress application running on the remote web server is affected
by multiple vulnerabilities:
  - An open redirect vulnerability exists in WordPress due to improper sanitization of user-supplied input to HTTP 
  request parameters. An unauthenticated, remote attacker can exploit this, by convincing a user to click a specially 
  crafted link, to redirect a user to a malicious website. (CVE-2019-16220)

  - Multiple cross-site scripting (XSS) vulnerabilities exist in WordPress due to improper validation of user-supplied 
  input before returning it to users. An unauthenticated, remote attacker can exploit this, by convincing a user to 
  click a specially crafted URL, to execute arbitrary script code in a user's browser session. 
  (CVE-2019-16217, CVE-2019-16218, CVE-2019-16219, CVE-2019-16221, CVE-2019-16222, CVE-2019-16223)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://core.trac.wordpress.org/query?status=closed&resolution=fixed&milestone=5.2.3&order=priority
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?721eeb41");
  script_set_attribute(attribute:"see_also", value:"https://codex.wordpress.org/WordPress_Versions");
  script_set_attribute(attribute:"see_also", value:"https://wordpress.org/support/wordpress-version/version-3-7-30/");
  script_set_attribute(attribute:"see_also", value:"https://wordpress.org/support/wordpress-version/version-3-8-30/");
  script_set_attribute(attribute:"see_also", value:"https://wordpress.org/support/wordpress-version/version-3-9-28/");
  script_set_attribute(attribute:"see_also", value:"https://wordpress.org/support/wordpress-version/version-4-0-27/");
  script_set_attribute(attribute:"see_also", value:"https://wordpress.org/support/wordpress-version/version-4-1-27/");
  script_set_attribute(attribute:"see_also", value:"https://wordpress.org/support/wordpress-version/version-4-2-24/");
  script_set_attribute(attribute:"see_also", value:"https://wordpress.org/support/wordpress-version/version-4-3-20/");
  script_set_attribute(attribute:"see_also", value:"https://wordpress.org/support/wordpress-version/version-4-4-19/");
  script_set_attribute(attribute:"see_also", value:"https://wordpress.org/support/wordpress-version/version-4-5-18/");
  script_set_attribute(attribute:"see_also", value:"https://wordpress.org/support/wordpress-version/version-4-6-15/");
  script_set_attribute(attribute:"see_also", value:"https://wordpress.org/support/wordpress-version/version-4-7-14/");
  script_set_attribute(attribute:"see_also", value:"https://wordpress.org/support/wordpress-version/version-4-8-10/");
  script_set_attribute(attribute:"see_also", value:"https://wordpress.org/support/wordpress-version/version-4-9-11/");
  script_set_attribute(attribute:"see_also", value:"https://wordpress.org/support/wordpress-version/version-5-0-6/");
  script_set_attribute(attribute:"see_also", value:"https://wordpress.org/support/wordpress-version/version-5-1-2/");
  script_set_attribute(attribute:"see_also", value:"https://wordpress.org/support/wordpress-version/version-5-2-3/");
  script_set_attribute(attribute:"solution", value:
"Upgrade to WordPress version 3.7.30 / 3.8.30 / 3.9.28 / 4.0.27 /
4.1.27 / 4.2.24 / 4.3.20 / 4.4.19 / 4.5.18 / 4.6.15 / 4.7.14 / 4.8.10 / 4.9.11 / 5.0.6 / 5.1.2 / 5.2.3 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-16220");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/09/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/09/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/09/09");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:wordpress:wordpress");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2019-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("wordpress_detect.nasl");
  script_require_keys("www/PHP", "installed_sw/WordPress", "Settings/ParanoidReport");
  script_require_ports("Services/www", 80, 443);

  exit(0);
}

include('vcf.inc');
include('http.inc');

app = 'WordPress';
get_install_count(app_name:app, exit_if_zero:TRUE);

if (report_paranoia < 2) audit(AUDIT_PARANOID);

port = get_http_port(default:80, php:TRUE);

app_info = vcf::get_app_info(app:'WordPress', port:port, webapp:TRUE);

# Wordpress backports Security fixes: 
# https://codex.wordpress.org/WordPress_Versions
constraints = [
  {'fixed_version':'3.7.30', 'fixed_display':'3.7.30 / 5.2.3 or later'},
  {'min_version':'3.8', 'fixed_version':'3.8.30', 'fixed_display':'3.8.30 / 5.2.3 or later' },
  {'min_version':'3.9', 'fixed_version':'3.9.28', 'fixed_display':'3.9.28 / 5.2.3 or later' },
  {'min_version':'4.0', 'fixed_version':'4.0.27', 'fixed_display':'4.0.27 / 5.2.3 or later' },
  {'min_version':'4.1', 'fixed_version':'4.1.27', 'fixed_display':'4.1.27 / 5.2.3 or later' },
  {'min_version':'4.2', 'fixed_version':'4.2.24', 'fixed_display':'4.2.24 / 5.2.3 or later' },
  {'min_version':'4.3', 'fixed_version':'4.3.20', 'fixed_display':'4.3.20 / 5.2.3 or later' },
  {'min_version':'4.4', 'fixed_version':'4.4.19', 'fixed_display':'4.4.19 / 5.2.3 or later' },
  {'min_version':'4.5', 'fixed_version':'4.5.18', 'fixed_display':'4.5.18 / 5.2.3 or later' },
  {'min_version':'4.6', 'fixed_version':'4.6.15', 'fixed_display':'4.6.15 / 5.2.3 or later' },
  {'min_version':'4.7', 'fixed_version':'4.7.14', 'fixed_display':'4.7.14 / 5.2.3 or later' },
  {'min_version':'4.8', 'fixed_version':'4.8.10', 'fixed_display':'4.8.10 / 5.2.3 or later' },
  {'min_version':'4.9', 'fixed_version':'4.9.11', 'fixed_display':'4.9.11 / 5.2.3 or later' },
  {'min_version':'5.0', 'fixed_version':'5.0.6', 'fixed_display':'5.0.6 / 5.2.3 or later' },
  {'min_version':'5.1', 'fixed_version':'5.1.2', 'fixed_display':'5.1.2 / 5.2.3 or later' },
  {'min_version':'5.2', 'fixed_version':'5.2.3'}
];

vcf::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_WARNING,
  flags:{xss:TRUE}
);
