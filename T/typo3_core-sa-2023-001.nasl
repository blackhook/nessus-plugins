#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(171074);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/02/17");

  script_cve_id("CVE-2023-24814");

  script_name(english:"TYPO3 8.7.0 < 8.7.51 ELTS / 9.0.0 < 9.5.40 ELTS / 10.0.0 < 10.4.36 / 11.0.0 < 11.5.23 / 12.0.0 < 12.2.0 XSS (TYPO3-CORE-SA-2023-001)");

  script_set_attribute(attribute:"synopsis", value:
"The remote webserver is affected by a XSS vulnerability");
  script_set_attribute(attribute:"description", value:
"The version of TYPO3 installed on the remote host is prior to 8.7.0 < 8.7.51 ELTS / 9.0.0 < 9.5.40 ELTS / 10.0.0 <
10.4.36 / 11.0.0 < 11.5.23 / 12.0.0 < 12.2.0. It is, therefore, affected by a vulnerability as referenced in the
TYPO3-CORE-SA-2023-001 advisory.

  - TYPO3 core component GeneralUtility::getIndpEnv() uses the unfiltered server environment variable
    PATH_INFO, which allows attackers to inject malicious content. In combination with the TypoScript setting
    config.absRefPrefix=auto, attackers can inject malicious HTML code into pages that have not yet been
    rendered and cached. As a result, injected values would be cached and delivered to other website visitors
    (persisted cross-site scripting). Individual code which relies on the resolved value of
    GeneralUtility::getIndpEnv('SCRIPT_NAME') and corresponding usages (as shown below) are vulnerable as
    well. GeneralUtility::getIndpEnv('PATH_INFO') GeneralUtility::getIndpEnv('SCRIPT_NAME')
    GeneralUtility::getIndpEnv('TYPO3_REQUEST_DIR') GeneralUtility::getIndpEnv('TYPO3_REQUEST_SCRIPT')
    GeneralUtility::getIndpEnv('TYPO3_SITE_PATH') GeneralUtility::getIndpEnv('TYPO3_SITE_SCRIPT')
    GeneralUtility::getIndpEnv('TYPO3_SITE_URL') Installations of TYPO3 versions 8.7 and 9.x are probably only
    affected when server environment variable TYPO3_PATH_ROOT is defined - which is the case if they were
    installed via Composer. Additional investigations confirmed that Apache and Microsoft IIS web servers
    using PHP-CGI (FPM, FCGI/FastCGI, or similar) are affected. There might be the risk that nginx is
    vulnerable as well. It was not possible to exploit Apache/mod_php scenarios. (CVE-2023-24814)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://typo3.org/security/advisory/typo3-core-sa-2023-001");
  script_set_attribute(attribute:"solution", value:
"Upgrade to TYPO3 8.7.51 ELTS, 9.5.40 ELTS, 10.4.36, 11.5.23, 12.2.0 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-24814");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/02/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/02/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/02/07");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:typo3:typo3");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("typo3_detect.nasl");
  script_require_keys("installed_sw/TYPO3", "www/PHP");
  script_require_ports("Services/www", 80);

  exit(0);
}

include('vcf.inc');
include('http.inc');

port = get_http_port(default:80, php:TRUE);
app_info = vcf::get_app_info(app:'TYPO3', port:port, webapp:TRUE);

var constraints = [
  { 'min_version' : '8.7.0', 'max_version' : '8.7.50', 'fixed_version' : '8.7.51', 'fixed_display' : '8.7.51 ELTS' },
  { 'min_version' : '9.0.0', 'max_version' : '9.5.39', 'fixed_version' : '9.5.40', 'fixed_display' : '9.5.40 ELTS' },
  { 'min_version' : '10.0.0', 'max_version' : '10.4.34', 'fixed_version' : '10.4.36' },
  { 'min_version' : '11.0.0', 'max_version' : '11.5.22', 'fixed_version' : '11.5.23' },
  { 'min_version' : '12.0.0', 'max_version' : '12.1.3', 'fixed_version' : '12.2.0' }
];

vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_WARNING,
    flags:{'xss':TRUE}
);
