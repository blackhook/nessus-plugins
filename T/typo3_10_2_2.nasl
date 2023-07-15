#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(138510);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/12");

  script_cve_id("CVE-2019-19848", "CVE-2019-19849", "CVE-2019-19850");

  script_name(english:"TYPO3 8.x < 8.7.30 / 9.x < 9.5.12 / 10.x < 10.2.2 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP script that is affected by multiple vulnerabilities");
  script_set_attribute(attribute:"description", value:
"The version of TYPO3 installed on the remote host is 8.x prior to 8.7.30, 9.x prior to 9.5.12 or 10.x prior to 10.2.2.
It is, therefore, affected by multiple vulnerabilities:
  - A directory traversal vulnerability exists in Typo3's extension manager. An authenticated, remote
  attacker can exploit this, by sending a URI that contains directory traversal characters, to disclose
  the contents of files located outside of the server's restricted path (CVE-2019-19848).

  - An unsecure deserialization vulnerability exists in Typo3's QueryGenerator & QueryView classes. An 
  authenticated, remote attacker could exploit this, via a specially crafted object, to execute arbitary
  code on an affected host (CVE-2019-19849).

  - A SQL injection (SQLi) vulnerability exists in Typo's QueryGenerator class due to improper validation
  of user-supplied input. An authenticated, remote attacker can exploit this to inject or manipulate SQL 
  queries in the back-end database, resulting in the disclosure or manipulation of arbitrary data
  (CVE-2019-19850).

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version");
  # https://typo3.org/security/advisory/typo3-core-sa-2019-021
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d5b40217");
  # https://typo3.org/security/advisory/typo3-core-sa-2019-022
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?44aaf5c0");
  # https://typo3.org/security/advisory/typo3-core-sa-2019-023
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d12a1db6");
  # https://typo3.org/security/advisory/typo3-core-sa-2019-024
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?80ade2aa");
  # https://typo3.org/security/advisory/typo3-core-sa-2019-025
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b88f654b");
  # https://typo3.org/security/advisory/typo3-core-sa-2019-026
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?8fb55544");
  script_set_attribute(attribute:"solution", value:
"Upgrade to TYPO3 8.7.30, 9.5.12, 10.2.2 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-19850");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2019-19849");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/12/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/12/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/07/15");

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
  {'min_version':'8.0' , 'fixed_version':'8.7.30'},
  {'min_version':'9.0' , 'fixed_version':'9.5.12'},
  {'min_version':'10.0', 'fixed_version':'10.2.2'}
];

vcf::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_WARNING
);
