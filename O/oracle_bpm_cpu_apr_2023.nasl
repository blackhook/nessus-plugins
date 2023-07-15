#%NASL_MIN_LEVEL 70300
##
# (C) Tenable, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(174472);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/21");

  script_cve_id(
    "CVE-2022-45047",
    "CVE-2022-42890",
    "CVE-2022-42003",
    "CVE-2022-36033"
  );
  script_xref(name:"IAVA", value:"2023-A-0210");

  script_name(english:"Oracle Business Process Management Suite (Apr 2023 CPU)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Oracle Business Process Management Suite installed on the remote host is affected by multiple
vulnerabilities, as referenced in the April 2023 CPU advisory. Specifically:

  - Class org.apache.sshd.server.keyprovider.SimpleGeneratorHostKeyProvider in Apache MINA SSHD <= 2.9.1 uses
    Java deserialization to load a serialized java.security.PrivateKey. The class is one of several implementations
    that an implementor using Apache MINA SSHD can choose for loading the host keys of an SSH server.
    (CVE-2022-45047)

  - In FasterXML jackson-databind before 2.14.0-rc1, resource exhaustion can occur because of a lack of a check in
    primitive value deserializers to avoid deep wrapper array nesting, when the UNWRAP_SINGLE_VALUE_ARRAYS feature
    is enabled. Additional fix version in 2.13.4.1 and 2.12.17.1 (CVE-2022-42003)

  - A vulnerability in Batik of Apache XML Graphics allows an attacker to run Java code from untrusted SVG via
    JavaScript. This issue affects Apache XML Graphics prior to 1.16. Users are recommended to upgrade to version
    1.16. (CVE-2022-42890)

  - jsoup is a Java HTML parser, built for HTML editing, cleaning, scraping, and cross-site scripting (XSS) safety.
    jsoup may incorrectly sanitize HTML including `javascript:` URL expressions, which could allow XSS attacks when
    a reader subsequently clicks that link. If the non-default `SafeList.preserveRelativeLinks` option is enabled,
    HTML including `javascript:` URLs that have been crafted with control characters will not be sanitized. If the
    site that this HTML is published on does not set a Content Security Policy, an XSS attack is then possible. This
    issue is patched in jsoup 1.15.3. Users should upgrade to this version. Additionally, as the unsanitized input
    may have been persisted, old content should be cleaned again using the updated version. (CVE-2022-36033)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version   
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/security-alerts/cpuapr2023.html");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the April 2023 Oracle Critical Patch Update advisory.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-45047");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/04/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/04/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/04/19");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:business_process_management_suite");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("oracle_bpm_installed.nbin");
  script_require_keys("installed_sw/Oracle Business Process Manager");

  exit(0);
}

include('vcf.inc');
var app_info = vcf::get_app_info(app:'Oracle Business Process Manager');

var constraints = [
  { 'min_version':'12.2.1.4.0', 'fixed_version' : '12.2.1.4.230404' }
];

vcf::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_HOLE
);
