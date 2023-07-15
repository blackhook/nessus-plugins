#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(166752);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/11/02");

  script_cve_id("CVE-2021-41184", "CVE-2022-29096", "CVE-2022-29097");

  script_name(english:"Dell Wyse Management Suite < 3.7 Multiple Vulnerabilities (DSA-2022-143)");

  script_set_attribute(attribute:"synopsis", value:
"Dell Wyse Management Suite installed on the local host is affected by a vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Dell Wyse Management Suite installed on the remote host is prior to tested version. It is, therefore,
affected by a vulnerability as referenced in the DSA-2022-143 advisory.

  - jQuery-UI is the official jQuery user interface library. Prior to version 1.13.0, accepting the value of
    the 'of' option of the '.position()' util from untrusted sources may execute untrusted code. The issue is
    fixed in jQuery UI 1.13.0. Any string value passed to the 'of' option is now treated as a CSS selector. A
    workaround is to not accept the value of the 'of' option from untrusted sources. (CVE-2021-41184)

  - Dell Wyse Management Suite 3.6.1 and below contains a Reflected Cross-Site Scripting Vulnerability in
    saveGroupConfigurations page. An authenticated attacker could potentially exploit this vulnerability,
    leading to the execution of malicious HTML or JavaScript code in a victim user's web browser in the
    context of the vulnerable web application. Exploitation may lead to information disclosure, session theft,
    or client-side request forgery. (CVE-2022-29096)

  - Dell WMS 3.6.1 and below contains a Path Traversal vulnerability in Device API. A remote attacker could
    potentially exploit this vulnerability, to gain unauthorized read access to the files stored on the server
    filesystem, with the privileges of the running web application. (CVE-2022-29097)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://www.dell.com/support/kbdoc/en-us/000200215/dsa-2022-143-dell-wyse-management-suite-security-update-for-multiple-vulnerabilities
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?1b6156fc");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Dell Wyse Management Suite version 3.7 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-41184");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/05/31");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/05/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/11/01");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:dell:wyse_management_suite");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("dell_wyse_management_suite_win_installed.nbin");
  script_require_keys("installed_sw/Dell Wyse Management Suite");

  exit(0);
}

include('vcf.inc');

var app_info = vcf::get_app_info(app:'Dell Wyse Management Suite', win_local:TRUE);

var constraints = [
  { 'fixed_version' : '3.7' }
];

vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_WARNING,
    flags:{'xss':TRUE}
);
