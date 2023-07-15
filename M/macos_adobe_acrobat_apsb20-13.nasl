#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(134703);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/02/12");

  script_cve_id(
    "CVE-2020-3792",
    "CVE-2020-3793",
    "CVE-2020-3795",
    "CVE-2020-3797",
    "CVE-2020-3799",
    "CVE-2020-3800",
    "CVE-2020-3801",
    "CVE-2020-3802",
    "CVE-2020-3803",
    "CVE-2020-3804",
    "CVE-2020-3805",
    "CVE-2020-3806",
    "CVE-2020-3807"
  );
  script_xref(name:"IAVA", value:"2020-A-0106-S");

  script_name(english:"Adobe Acrobat <= 2015.006.30510 / 2017.011.30158 / 2020.006.20034 Multiple Vulnerabilities (APSB20-13) (macOS)");

  script_set_attribute(attribute:"synopsis", value:
"The version of Adobe Acrobat installed on the remote macOS host is
affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Adobe Acrobat installed on the remote macOS host is a version prior or equal to 2015.006.30510,
2017.011.30158, or 2020.006.20034. It is, therefore, affected by multiple vulnerabilities.

  - Out-of-bounds read potentially leading to Information
    Disclosure (CVE-2020-3804, CVE-2020-3806)

  - Out-of-bounds write potentially leading to Arbitrary
    Code Execution (CVE-2020-3795)

  - Stack-based buffer overflow potentially leading to
    Arbitrary Code Execution (CVE-2020-3799)

  - Use-after-free potentially leading to Arbitrary Code
    Execution (CVE-2020-3792, CVE-2020-3793, CVE-2020-3801,
    CVE-2020-3802, CVE-2020-3805)

  - Memory address leak potentially leading to Information
    Disclosure (CVE-2020-3800)

  - Buffer overflow potentially leading to Arbitrary Code
    Execution (CVE-2020-3807)

  - Memory corruption potentially leading to Arbitrary Code
    Execution (CVE-2020-3797)

  - Insecure library loading (DLL hijacking) potentially
    leading to Privilege Escalation (CVE-2020-3803)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://helpx.adobe.com/security/products/acrobat/apsb20-13.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Adobe Acrobat version 2015.006.30518 or 2017.011.30166 or 2020.006.20042 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-3805");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/03/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/03/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/03/19");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:acrobat");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2020-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("macosx_adobe_acrobat_installed.nbin");
  script_require_keys("Host/local_checks_enabled", "Host/MacOSX/Version", "installed_sw/Adobe Acrobat");

  exit(0);
}

include('vcf.inc');
include('vcf_extras.inc');

get_kb_item_or_exit('Host/local_checks_enabled');
os = get_kb_item('Host/MacOSX/Version');
if (empty_or_null(os)) audit(AUDIT_OS_NOT, 'Mac OS X');

app_info = vcf::get_app_info(app:'Adobe Acrobat');

# vcf::adobe_reader::check_version_and_report will
# properly separate tracks when checking constraints.
# x.y.30zzz = DC Classic
# x.y.20zzz = DC Continuous
constraints = [
  { 'min_version' : '15.6', 'max_version' : '15.006.30510', 'fixed_version' : '15.006.30518' },
  { 'min_version' : '17.8', 'max_version' : '17.011.30158', 'fixed_version' : '17.011.30166' },
  { 'min_version' : '15.7', 'max_version' : '20.006.20034', 'fixed_version' : '20.006.20042' }
];
vcf::adobe_reader::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE, max_segs:3);
