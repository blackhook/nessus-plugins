#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(168661);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/13");

  script_cve_id("CVE-2022-23499");

  script_name(english:"TYPO3 8.0.0 < 8.7.49 ELTS / 9.0.0 < 9.5.38 ELTS / 10.0.0 < 10.4.33 / 11.0.0 < 11.5.20 / 12.0.0 < 12.1.1 XSS (TYPO3-CORE-SA-2022-017)");

  script_set_attribute(attribute:"synopsis", value:
"The remote webserver is affected by a XSS vulnerability");
  script_set_attribute(attribute:"description", value:
"The version of TYPO3 installed on the remote host is prior to 8.0.0 < 8.7.49 ELTS / 9.0.0 < 9.5.38 ELTS / 10.0.0 <
10.4.33 / 11.0.0 < 11.5.20 / 12.0.0 < 12.1.1. It is, therefore, affected by a vulnerability as referenced in the
TYPO3-CORE-SA-2022-017 advisory.

  - Due to a parsing issue in the upstream package masterminds/html5, malicious markup used in a sequence with
    special HTML CDATA sections cannot be filtered and sanitized. This allows bypassing the cross-site
    scripting mechanism of typo3/html-sanitizer. Besides that, the upstream package masterminds/html5 provides
    HTML raw text elements (script, style, noframes, noembed and iframe) as DOMText nodes, which were not
    processed and sanitized further. None of the mentioned elements were defined in the default builder
    configuration, that's why only custom behaviors, using one of those tag names, were vulnerable to cross-
    site scripting. (CVE-2022-23499)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://typo3.org/security/advisory/typo3-core-sa-2022-017");
  script_set_attribute(attribute:"solution", value:
"Upgrade to TYPO3 8.7.49 ELTS, 9.5.38 ELTS, 10.4.33, 11.5.20, 12.1.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-23499");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/12/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/12/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/12/13");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:typo3:typo3");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
  { 'min_version' : '8.0.0', 'max_version' : '8.7.48', 'fixed_version' : '8.7.49', 'fixed_display' : '8.7.49 ELTS' },
  { 'min_version' : '9.0.0', 'max_version' : '9.5.37', 'fixed_version' : '9.5.38', 'fixed_display' : '9.5.38 ELTS' },
  { 'min_version' : '10.0.0', 'max_version' : '10.4.32', 'fixed_version' : '10.4.33' },
  { 'min_version' : '11.0.0', 'max_version' : '11.5.19', 'fixed_version' : '11.5.20' },
  { 'min_version' : '12.0.0', 'max_version' : '12.1.0', 'fixed_version' : '12.1.1' }
];

vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_WARNING,
    flags:{'xss':TRUE}
);
