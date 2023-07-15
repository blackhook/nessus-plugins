#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(138612);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/02");

  script_cve_id("CVE-2019-12747");

  script_name(english:"TYPO3 8.x < 8.7.27 / 9.x < 9.5.8 Multiple Vulnerabilities ");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application which is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of TYPO3 installed on the remote host is 8.x prior to 8.7.27 or 9.x prior to 9.5.8. It is, therefore,
affected by multiple vulnerabilities:
  - An insecure deserialization vulnerability exists in Typo3's FormEngine & DataHandler components.
  An unauthenticated, remote attacker, by sending a specially crafted object, to execute arbitrary code
  on an affected host (CVE-2019-12747).

  - A cross-site scripting (XSS) vulnerability exists in Typo3's Page TSConfig component due to improper
  validation of user-supplied input before returning it to users. An unauthenticated, remote attacker 
  can exploit this, by convincing a user to click a specially crafted URL, to execute arbitrary script
  code in a user's browser session.

  - A remote code execution vulnerability exists in Typo3's Page TSConfig component due to insufficient
  validation of user-supplied input. An unauthenticated, remote attacker can exploit this execute arbitrary
  commands on an affected host.

  - An information disclosure vulnerability exists in Typo3. An unauthenticated, remote attacker can exploit
  this to disclose potentially sensitive information.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version");
  # https://typo3.org/security/advisory/typo3-core-sa-2019-020
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a2e6e8ab");
  # https://typo3.org/security/advisory/typo3-core-sa-2019-019
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?fa28e011");
  # https://typo3.org/security/advisory/typo3-core-sa-2019-014
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?cbe52c52");
  script_set_attribute(attribute:"solution", value:
"Upgrade to TYPO3 8.7.27, 9.5.8 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-12747");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/06/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/06/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/07/20");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:typo3:typo3");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2020-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
  {'min_version':'8.0' , 'fixed_version':'8.7.27'},
  {'min_version':'9.0', 'fixed_version':'9.5.8'}
];

vcf::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_WARNING,
  flags:{'xss':TRUE}
);
