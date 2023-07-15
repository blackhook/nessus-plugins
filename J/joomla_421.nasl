#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(164533);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/02/03");

  script_cve_id("CVE-2022-27911");
  script_xref(name:"IAVA", value:"2022-A-0345-S");
  script_xref(name:"IAVA", value:"2022-A-0490-S");

  script_name(english:"Joomla 4.2.0 < 4.2.1 Joomla 4.2.1 Security and Bug Fix Release (5866-joomla-4-2-1-release)");

  script_set_attribute(attribute:"synopsis", value:
"A PHP application running on the remote web server is affected by a vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the instance of Joomla! running on the remote web server is 4.2.0 prior to
4.2.1. It is, therefore, affected by a vulnerability.

  - An issue was discovered in Joomla! 4.2.0. Multiple Full Path Disclosures because of missing '_JEXEC or die
    check' caused by the PSR12 changes. (CVE-2022-27911)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://www.joomla.org/announcements/release-news/5866-joomla-4-2-1-release.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?8c0a1f1f");
  # https://developer.joomla.org/security-centre/884-20220801-core-multiple-full-path-disclosures-because-of-missing-jexec-or-die-check.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?77f7b004");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Joomla! version 4.2.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-27911");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/08/30");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/08/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/08/31");

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
  { 'fixed_version' : '4.2.1', 'equal' : '4.2.0' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
