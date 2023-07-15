#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(166467);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/02/03");

  script_cve_id("CVE-2022-27912", "CVE-2022-27913");
  script_xref(name:"IAVA", value:"2022-A-0450-S");
  script_xref(name:"IAVA", value:"2022-A-0490-S");

  script_name(english:"Joomla 4.0.x < 4.2.4 Multiple Vulnerabilities (5870-joomla-4-2-4-security-release)");

  script_set_attribute(attribute:"synopsis", value:
"A PHP application running on the remote web server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the instance of Joomla! running on the remote web server is 4.0.x prior to
4.2.4. It is, therefore, affected by multiple vulnerabilities.

  - Joomla 4 sites with publicly enabled debug mode exposed data of previous requests. (CVE-2022-27912)

  - Inadequate filtering of potentially malicious user input leads to reflected XSS vulnerabilities in various
    components. (CVE-2022-27913)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://www.joomla.org/announcements/release-news/5870-joomla-4-2-4-security-release.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?15db7046");
  # https://developer.joomla.org/security-centre/885-20221001-core-disclosure-of-critical-information-in-debug-mode.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a0a135c4");
  # https://developer.joomla.org/security-centre/886-20221002-core-reflected-xss-in-various-components
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f2e6b41a");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Joomla! version 4.2.4 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-27913");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/10/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/10/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/10/25");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:joomla:joomla\!");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
  { 'min_version' : '4.0.0', 'max_version' : '4.2.3', 'fixed_version' : '4.2.4' }
];

vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_WARNING,
    flags:{'xss':TRUE}
);
