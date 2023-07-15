#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(103383);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2017-14595", "CVE-2017-14596");
  script_bugtraq_id(100898, 100900);

  script_name(english:"Joomla! 1.5.0 < 3.8.0 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the Joomla!
installation running on the remote web server is 1.5.0 or later but
prior to 3.8.0. It is, therefore, affected by the following
vulnerabilities :

  - A flaw exists related to SQL query handling that allows
    disclosure of article introduction text when such articles
    are in the archived state. Note that only versions
    3.7.0 through 3.7.5 are affected by this flaw.
    (CVE-2017-14595)

  - An input-validation flaw exists in the LDAP
    authentication plugin that allows disclosure of usernames
    and passwords. Note that Joomla! must be configured for
    LDAP authentication to be affected. (CVE-2017-14596)

Note that Nessus has not attempted to exploit these issues but has
instead relied only on the application's self-reported version number.");
  # https://developer.joomla.org/security-centre/711-20170902-core-ldap-information-disclosure
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d2d49f37");
  # https://developer.joomla.org/security-centre/710-20170901-core-information-disclosure
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f49184a2");
  # https://www.joomla.org/announcements/release-news/5713-joomla-3-8-0-release.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?3c8b295a");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Joomla! version 3.8.0 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:X");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-14596");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/09/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/09/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/09/21");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:joomla:joomla\!");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2017-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("joomla_detect.nasl");
  script_require_keys("installed_sw/Joomla!", "www/PHP", "Settings/ParanoidReport");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("http.inc");
include("vcf.inc");

port = get_http_port(default:80, php:TRUE);

if (report_paranoia < 2) audit(AUDIT_PARANOID);

app_info = vcf::get_app_info(app:"Joomla!", port:port, webapp:TRUE);

vcf::check_granularity(app_info:app_info, sig_segments:3);

constraints = [
  { "min_version" : "1.5.0", "max_version" : "3.7.5", "fixed_version" : "3.8.0" }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
