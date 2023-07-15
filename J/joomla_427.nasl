#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(170940);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/02/24");

  script_cve_id("CVE-2023-23750", "CVE-2023-23751");
  script_xref(name:"IAVA", value:"2023-A-0062-S");

  script_name(english:"Joomla 4.0.x < 4.2.7 Multiple Vulnerabilities (5876-joomla-4-2-7-security-and-bug-fix-release)");

  script_set_attribute(attribute:"synopsis", value:
"A PHP application running on the remote web server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the instance of Joomla! running on the remote web server is 4.0.x prior to
4.2.7. It is, therefore, affected by multiple vulnerabilities.

  - An issue was discovered in Joomla! 4.0.0 through 4.2.6. A missing token check causes a CSRF vulnerability
    in the handling of post-installation messages. (CVE-2023-23750)

  - An issue was discovered in Joomla! 4.0.0 through 4.2.4. A missing ACL check allows non super-admin users
    to access com_actionlogs. (CVE-2023-23751)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://www.joomla.org/announcements/release-news/5876-joomla-4-2-7-security-and-bug-fix-release.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0930a3a7");
  # https://developer.joomla.org/security-centre/890-20230101-core-csrf-within-post-installation-messages
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?601b8791");
  # https://developer.joomla.org/security-centre/891-20230102-core-missing-acl-checks-for-com-actionlogs.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b77d9a3d");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Joomla! version 4.2.7 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-23750");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/01/31");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/01/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/02/02");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:joomla:joomla\!");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("joomla_detect.nasl");
  script_require_keys("installed_sw/Joomla!", "www/PHP", "Settings/ParanoidReport");
  script_require_ports("Services/www", 80);

  exit(0);
}

include('vcf.inc');
include('http.inc');

if (report_paranoia < 2) audit(AUDIT_PARANOID);

var port = get_http_port(default:80, php:TRUE);

var app_info = vcf::get_app_info(app:'Joomla!', port:port, webapp:TRUE);

vcf::check_granularity(app_info:app_info, sig_segments:3);

var constraints = [
  { 'min_version' : '4.0.0', 'max_version' : '4.2.6', 'fixed_version' : '4.2.7' }
];

vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_HOLE,
    flags:{'xsrf':TRUE}
);
