##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(163271);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/08");

  script_cve_id(
    "CVE-2022-29090",
    "CVE-2022-33924",
    "CVE-2022-33925",
    "CVE-2022-33926",
    "CVE-2022-33927",
    "CVE-2022-33928",
    "CVE-2022-33929",
    "CVE-2022-33930",
    "CVE-2022-33931",
    "CVE-2022-34365"
  );

  script_name(english:"Dell Wyse Management Suite < 3.8 Multiple Vulnerabilities (DSA-2022-134)");

  script_set_attribute(attribute:"synopsis", value:
"Dell Wyse Management Suite installed on the local host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Dell Wyse Management Suite installed on the remote host is prior to 3.8. It is, therefore, affected by
multiple vulnerabilities as referenced in the DSA-2022-134 advisory.

  - Wyse Management Suite 3.7 and earlier contains a Sensitive Data Exposure vulnerability. A low privileged
    malicious user may potentially exploit this vulnerability in order to obtain credentials. The attacker may
    be able to use the exposed credentials to access the target device and perform unauthorized actions.
    (CVE-2022-29090)

  - Wyse Management Suite 3.7 and earlier contains an Improper Access control vulnerability with which an
    attacker with no access to create rules may potentially exploit this vulnerability and create rules. The
    attacker may create a schedule to run the rule. (CVE-2022-33924)

  - Wyse Management Suite 3.7 and earlier contains an Improper Access control vulnerability in UI. A remote
    authenticated attacker may potentially exploit this vulnerability by bypassing access controls in order to
    download reports containing sensitive information. (CVE-2022-33925)

  - Wyse Management Suite 3.7 and earlier contains an improper access control vulnerability. A remote
    malicious user may exploit this vulnerability in order to retain access to a file repository after it has
    been revoked. (CVE-2022-33926)

  - Wyse Management Suite 3.7 and earlier contains a Session Fixation vulnerability. An unauthenticated
    attacker may exploit this by taking advantage of a user with multiple active sessions in order to hijack a
    user's session. (CVE-2022-33927)

  - Wyse Management Suite 3.7 and earlier contains a Plain-text Password Storage Vulnerability in UI. An
    attacker with low privileges may potentially exploit this vulnerability, leading to the disclosure of
    certain user credentials. The attacker may be able to use the exposed credentials to access the vulnerable
    application with privileges of the compromised account. (CVE-2022-33928)

  - Wyse Management Suite 3.7 and earlier contains a Reflected Cross-Site Scripting Vulnerability in
    EndUserSummary page. An authenticated attacker may potentially exploit this vulnerability, leading to the
    execution of malicious HTML or JavaScript code in a victim user's web browser in the context of the
    vulnerable web application. Exploitation may lead to information disclosure, session theft, or client-side
    request forgery. (CVE-2022-33929)

  - Wyse Management Suite 3.7 and earlier contains Information Disclosure in Devices error pages. An attacker
    may potentially exploit this vulnerability, leading to the disclosure of certain sensitive information.
    The attacker may be able to use the exposed information for access and further vulnerability research.
    (CVE-2022-33930)

  - Wyse Management Suite 3.7 and earlier contains an Improper Access control vulnerability in UI. An attacker
    with no access to Alert Classification page may potentially exploit this vulnerability, leading to
    changing the alert categories. (CVE-2022-33931)

  - Wyse Management Suite 3.7 contains a Path Traversal Vulnerability in Device API. Anattackermay
    potentially exploit thisvulnerability,to gain unauthorizedread access to the files stored on the server
    file system, with the privileges of the running web application. (CVE-2022-34365)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://www.dell.com/support/kbdoc/en-us/000201383/dsa-2022-134-dell-wyse-management-suite-security-update-for-multiple-vulnerabilities
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?7f6cc9f8");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Dell Wyse Management Suite version 3.8 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-33928");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/07/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/07/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/07/19");

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
  { 'fixed_version' : '3.8' }
];
vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_HOLE,
    flags:{'xss':TRUE}
);
