#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(138385);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/12");

  script_cve_id(
    "CVE-2020-11064",
    "CVE-2020-11066",
    "CVE-2020-11067",
    "CVE-2020-11069"
  );

  script_name(english:"TYPO3 9.x < 9.5.17 / 10.x < 10.4.2 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP script that is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of TYPO3 installed on the remote host is 9.x prior to 9.5.17 or 10.x prior to 10.4.2. It is, therefore,
affected by multiple vulnerabilities:
  - A cross-site scripting (XSS) vulnerability exists in Typo3's form engine component due to improper
  validation of user-supplied input before returning it to users. An authenticated, remote attacker 
  can exploit this, by convincing a user to click a specially crafted URL, to execute arbitrary script
  code in a user's browser session (CVE-2020-11064).

  - Multiple insecure deserialization vulnerabilities exist in Typo3. An authenticated, remote attacker
  could exploit this, by crafting a specially crafted object, to execute arbitrary code
  on an affected host (CVE-2020-11066 & CVE-2020-11067).

  - A server-side request forgery vulnerability exists in Typo3's backend user interface and install
  tool components. An unauthenticated, remote attacker could exploit this, by uploading a specially
  crafted file, to force the application to generate potentially malicious requests on their 
  behalf. (CVE-2020-11069).

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version");
  # https://typo3.org/security/advisory/typo3-core-sa-2020-002
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?910f6181");
  # https://typo3.org/security/advisory/typo3-core-sa-2020-004
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e5854bab");
  # https://typo3.org/security/advisory/typo3-core-sa-2020-005
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d58229ad");
  # https://typo3.org/security/advisory/typo3-core-sa-2020-006
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e039f653");
  script_set_attribute(attribute:"solution", value:
"Upgrade to TYPO3 9.5.17, 10.4.2 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-11069");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2020-11066");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/05/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/05/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/07/13");

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
  {'min_version':'9.0' , 'fixed_version':'9.5.17'},
  {'min_version':'10.0', 'fixed_version':'10.4.2'}
];

vcf::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_WARNING
);
