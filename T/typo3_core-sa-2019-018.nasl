#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(138599);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_name(english:"TYPO3 8.5.x < 8.7.27 / 9.x < 9.5.8 Session Hijacking (TYPO3-CORE-SA-2019-018)");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP script that is affected by a session hijacking vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of TYPO3 installed on the remote host is 8.5.x prior to 8.7.27 or 9.x prior to 9.5.8. It is, therefore,
affected by a session hijacking vulnerability due to a failure to properly clean up user sessions. When a user logs out
their session is transferred to that of the anonymous user. An unauthenticated, local attacker with access to the same
client application which a previously logged in user has utilised, can exploit this to perform actions in the context
of that user.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version");
  # https://typo3.org/security/advisory/typo3-core-sa-2019-018
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?47ca6560");
  script_set_attribute(attribute:"solution", value:
"Upgrade to TYPO3 8.7.27, 9.5.8 or later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:C/C:L/I:N/A:N");
  script_set_attribute(attribute:"cvss_score_source", value:"manual");
  script_set_attribute(attribute:"cvss_score_rationale", value:"Based on vendor advisory analysis");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/06/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/06/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/07/17");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:typo3:typo3");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2020-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("typo3_detect.nasl");
  script_require_keys("installed_sw/TYPO3", "www/PHP");
  script_require_ports("Services/www", 80);

  exit(0);
}

include('http.inc');
include('vcf.inc');

port = get_http_port(default:80, php:TRUE);
app_info = vcf::get_app_info(app:'TYPO3', port:port, webapp:TRUE);

constraints = [
  {'min_version':'8.5' , 'fixed_version':'8.7.27'},
  {'min_version':'9.0', 'fixed_version':'9.5.8'}
];

vcf::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_NOTE
);
