#
# (C) Tenable Network Security, Inc.
#

# The descriptive text and package checks in this plugin were
# extracted from WordPress Security Advisory wordpress-5-3-1-security-and-maintenance-release.

include('compat.inc');

if (description)
{
  script_id(132099);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/05/08");

  script_cve_id("CVE-2019-20042");
  script_xref(name:"IAVA", value:"2019-A-0462-S");

  script_name(english:"WordPress < 5.3.1");

  script_set_attribute(attribute:"synopsis", value:
"A PHP application running on the remote web server is affected by a vulnerability.");
  script_set_attribute(attribute:"description", value:
"WordPress versions 5.3.0 and earlier are affected by the following vulnerabilities:

  - Two cross-site scripting (XSS) vulnerabilities exist due to improper validation of user-supplied input.
    An unauthenticated, remote attacker can exploit these, by convincing a user to click a specially crafted
    URL, to execute arbitrary script code in a user's browser session. 

  - A remote, authenticated, unprivileged user can make a post sticky via the REST API.

  - wp_kses_bad_protcol() has been hardened to ensure that it is aware of the named colon attribute.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://wordpress.org/support/wordpress-version/version-5-3-1/");
  script_set_attribute(attribute:"solution", value:
"Upgrade to WordPress version 5.3.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-20042");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/12/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/12/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/12/18");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:wordpress:wordpress");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2019-2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("wordpress_detect.nasl");
  script_require_keys("www/PHP", "installed_sw/WordPress", "Settings/ParanoidReport");
  script_require_ports("Services/www", 80, 443);

  exit(0);
}

include('vcf.inc');
include('http.inc');

if (report_paranoia < 2) audit(AUDIT_PARANOID);

app = 'WordPress';
get_install_count(app_name:app, exit_if_zero:TRUE);
port = get_http_port(default:80, php:TRUE);

app_info = vcf::get_app_info(app:'WordPress', port:port, webapp:TRUE);

constraints = [
  { 'fixed_version' : '5.3.1' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING, flags:{xss:TRUE});
