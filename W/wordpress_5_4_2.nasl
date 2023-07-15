#
# (C) Tenable Network Security, Inc.
#

# The descriptive text and package checks in this plugin were
# extracted from WordPress Security Advisory wordpress-5-4-2-security-and-maintenance-release.

include('compat.inc');

if (description)
{
  script_id(137627);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/13");

  script_cve_id(
    "CVE-2020-4046",
    "CVE-2020-4047",
    "CVE-2020-4048",
    "CVE-2020-4049",
    "CVE-2020-4050"
  );
  script_xref(name:"IAVA", value:"2020-A-0266-S");

  script_name(english:"WordPress < 5.4.2");

  script_set_attribute(attribute:"synopsis", value:
"A PHP application running on the remote web server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the installation of WordPress installed on the remote host is affected
  by multiple vulnerabilities: 
    - Multiple cross-site scripting (XSS) vulnerabilities exist in Wordpress due to improper validation of 
      user-supplied input before returning it to users. An unauthenticated, remote attacker can exploit these
      , by convincing a user to click a specially crafted URL, to execute arbitrary script code in 
      a user's browser session (CVE-2020-4047, CVE-2020-4049).

    - An open-redirect vulnerability exists in Wordpress due to insufficient validation of user-supplied input.
      An unauthenticated, remote attack can exploit this to redirect users to potentially malicious sites 
      (CVE-2020-4048).
 
  Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported 
  version");
  # https://wordpress.org/news/2020/06/wordpress-5-4-2-security-and-maintenance-release/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?dd3bf98c");
  # https://make.wordpress.org/core/2020/06/09/wordpress-5-4-2-prevent-unmoderated-comments-from-search-engine-indexation/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?1aff0f95");
  script_set_attribute(attribute:"see_also", value:"https://wordpress.org/support/wordpress-version/version-5-4-2/");
  script_set_attribute(attribute:"solution", value:
"Upgrade to WordPress version 5.4.2 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:R/S:C/C:N/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-4050");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2020-4047");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/06/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/06/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/06/18");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:wordpress:wordpress");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2020-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("wordpress_detect.nasl");
  script_require_keys("www/PHP", "installed_sw/WordPress", "Settings/ParanoidReport");
  script_require_ports("Services/www", 80, 443);

  exit(0);
}

include('http.inc');
include('vcf.inc');

app = 'WordPress';
get_install_count(app_name:app, exit_if_zero:TRUE);

if (report_paranoia < 2)
  audit(AUDIT_PARANOID);

port = get_http_port(default:80, php:TRUE);
app_info = vcf::get_app_info(app:app, port:port, webapp:TRUE);

constraints = [
  { 'fixed_version' : '3.7.34' },
  { 'min_version' : '3.8', 'fixed_version' : '3.8.34' },
  { 'min_version' : '3.9', 'fixed_version' : '3.9.32' },
  { 'min_version' : '4.0', 'fixed_version' : '4.0.31' },
  { 'min_version' : '4.1', 'fixed_version' : '4.1.31' },
  { 'min_version' : '4.2', 'fixed_version' : '4.2.28' },
  { 'min_version' : '4.3', 'fixed_version' : '4.3.24' },
  { 'min_version' : '4.4', 'fixed_version' : '4.4.23' },
  { 'min_version' : '4.5', 'fixed_version' : '4.5.22' },
  { 'min_version' : '4.6', 'fixed_version' : '4.6.19' },
  { 'min_version' : '4.7', 'fixed_version' : '4.7.18' },
  { 'min_version' : '4.8', 'fixed_version' : '4.8.14' },
  { 'min_version' : '4.9', 'fixed_version' : '4.9.15' },
  { 'min_version' : '5.0', 'fixed_version' : '5.0.10' },
  { 'min_version' : '5.1', 'fixed_version' : '5.1.6'  },
  { 'min_version' : '5.2', 'fixed_version' : '5.2.7'  },
  { 'min_version' : '5.3', 'fixed_version' : '5.3.4'  },
  { 'min_version' : '5.4', 'fixed_version' : '5.4.2'  }
];

vcf::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_WARNING,
  flags: {'xss':TRUE}
);
