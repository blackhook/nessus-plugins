#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(139875);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2020-24597", "CVE-2020-24598", "CVE-2020-24599");
  script_xref(name:"IAVA", value:"2020-A-0393-S");

  script_name(english:"Joomla 2.5.x < 3.9.21 Multiple Vulnerabilities (5821-joomla-3-9-21)");

  script_set_attribute(attribute:"synopsis", value:
"A PHP application running on the remote web server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the instance of Joomla! running on the remote web server is 2.5.x prior to
3.9.21. It is, therefore, affected by multiple vulnerabilities.

  - Lack of escaping in mod_latestactions allows XSS attacks. (CVE-2020-24599)

  - Lack of input validation in com_content leads to an open redirect. (CVE-2020-24598)

  - Lack of input validation allows com_media root paths outside of the webroot. (CVE-2020-24597)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://www.joomla.org/announcements/release-news/5821-joomla-3-9-21.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?01923827");
  # https://developer.joomla.org/security-centre/824-20200801-core-xss-in-mod-latestactions.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?bf8b067d");
  # https://developer.joomla.org/security-centre/825-20200802-core-open-redirect-in-com-content-vote-feature.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?bf9882d4");
  # https://developer.joomla.org/security-centre/827-20200803-core-directory-traversal-in-com-media.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?592f5c43");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Joomla! version 3.9.21 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-24598");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/08/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/08/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/08/27");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:joomla:joomla\!");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2020-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("joomla_detect.nasl");
  script_require_keys("installed_sw/Joomla!", "www/PHP", "Settings/ParanoidReport");
  script_require_ports("Services/www", 80);

  exit(0);
}

include('vcf.inc');
include('http.inc');

if (report_paranoia < 2) audit(AUDIT_PARANOID);

port = get_http_port(default:80, php:TRUE);

app_info = vcf::get_app_info(app:'Joomla!', port:port, webapp:TRUE);

vcf::check_granularity(app_info:app_info, sig_segments:3);

constraints = [
  { 'min_version' : '2.5.0', 'max_version' : '3.9.20', 'fixed_version' : '3.9.21' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING, flags:{xss:TRUE});



