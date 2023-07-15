#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(166042);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/04");

  script_cve_id(
    "CVE-2022-35691",
    "CVE-2022-38437",
    "CVE-2022-38449",
    "CVE-2022-38450",
    "CVE-2022-42339",
    "CVE-2022-42342"
  );
  script_xref(name:"IAVA", value:"2022-A-0418-S");

  script_name(english:"Adobe Acrobat < 20.005.30407 / 22.003.20258 Multiple Vulnerabilities (APSB22-46) (macOS)");

  script_set_attribute(attribute:"synopsis", value:
"The version of Adobe Acrobat installed on the remote macOS host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Adobe Acrobat installed on the remote macOS host is a version prior to 20.005.30407 or 22.003.20258. It
is, therefore, affected by multiple vulnerabilities.

  - Adobe Acrobat Reader versions 22.002.20212 (and earlier) and 20.005.30381 (and earlier) are affected by a
    Stack-based Buffer Overflow vulnerability that could result in arbitrary code execution in the context of
    the current user. Exploitation of this issue requires user interaction in that a victim must open a
    malicious file. (CVE-2022-38450, CVE-2022-42339)

  - Adobe Acrobat Reader versions 22.002.20212 (and earlier) and 20.005.30381 (and earlier) are affected by a
    NULL Pointer Dereference vulnerability. An unauthenticated attacker could leverage this vulnerability to
    achieve an application denial-of-service in the context of the current user. Exploitation of this issue
    requires user interaction in that a victim must open a malicious file. (CVE-2022-35691)

  - Adobe Acrobat Reader versions 22.002.20212 (and earlier) and 20.005.30381 (and earlier) are affected by a
    Use After Free vulnerability that could lead to disclosure of sensitive memory. An attacker could leverage
    this vulnerability to bypass mitigations such as ASLR. Exploitation of this issue requires user
    interaction in that a victim must open a malicious file. (CVE-2022-38437)

  - Adobe Acrobat Reader versions 22.002.20212 (and earlier) and 20.005.30381 (and earlier) are affected by an
    out-of-bounds read vulnerability that could lead to disclosure of sensitive memory. An attacker could
    leverage this vulnerability to bypass mitigations such as ASLR. Exploitation of this issue requires user
    interaction in that a victim must open a malicious file. (CVE-2022-38449, CVE-2022-42342)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://helpx.adobe.com/security/products/acrobat/apsb22-46.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Adobe Acrobat version 20.005.30407 / 22.003.20258 or later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-42339");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(121, 125, 416, 476);

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/04/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/10/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/10/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:acrobat");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("macosx_adobe_acrobat_installed.nbin");
  script_require_keys("Host/local_checks_enabled", "Host/MacOSX/Version", "installed_sw/Adobe Acrobat");

  exit(0);
}

include('vcf.inc');
include('vcf_extras.inc');

get_kb_item_or_exit('Host/local_checks_enabled');
var os = get_kb_item('Host/MacOSX/Version');
if (empty_or_null(os)) audit(AUDIT_OS_NOT, 'Mac OS X');

var app_info = vcf::get_app_info(app:'Adobe Acrobat');

# vcf::adobe_reader::check_version_and_report will
# properly separate tracks when checking constraints.
# x.y.30zzz = DC Classic
# x.y.20zzz = DC Continuous
var constraints = [
  { 'min_version' : '15.7', 'max_version' : '22.002.20212', 'fixed_version' : '22.003.20258' },
  { 'min_version' : '20.1', 'max_version' : '20.005.30381', 'fixed_version' : '20.005.30407' }
];
vcf::adobe_reader::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE, max_segs:3);
