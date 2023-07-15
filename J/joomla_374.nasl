#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(102017);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2017-11364", "CVE-2017-11612");
  script_bugtraq_id(99952);

  script_name(english:"Joomla! 1.0.0 < 3.7.4 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the Joomla!
installation running on the remote web server is 1.0.0 or later but
prior to 3.7.4. It is, therefore, affected by the following
vulnerabilities :

  - A security bypass vulnerability exists in the installer
    application due to a failure to properly check for
    ownership of a webspace. An unauthenticated, remote
    attacker can exploit this to gain control of another
    user's webspace. Note that this vulnerability affects
    versions 1.0.0 through 3.7.3. (CVE-2017-11364)

  - A cross-site scripting (XSS) vulnerability exists due to
    improper validation of user-supplied input before
    returning it to users. An unauthenticated, remote
    attacker can exploit this, via a specially crafted
    request, to execute arbitrary script code in a user's
    browser session. Note that this vulnerability affects
    versions 1.5.0 through 3.7.3. (CVE-2017-11612)

Note that Nessus has not attempted to exploit these issues but has
instead relied only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"https://developer.joomla.org/security-centre/700-20170704");
  script_set_attribute(attribute:"see_also", value:"https://developer.joomla.org/security-centre/701-20170705");
  # https://www.joomla.org/announcements/release-news/5710-joomla-3-7-4-release.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d043319e");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Joomla! version 3.7.4 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:X");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-11364");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/07/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/07/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/07/27");

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
  { "min_version" : "1.0.0", "max_version" : "3.7.3", "fixed_version" : "3.7.4" }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING, flags:{xss:true});
