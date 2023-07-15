#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(156667);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/10/18");

  script_cve_id(
    "CVE-2021-44701",
    "CVE-2021-44702",
    "CVE-2021-44703",
    "CVE-2021-44704",
    "CVE-2021-44705",
    "CVE-2021-44706",
    "CVE-2021-44707",
    "CVE-2021-44708",
    "CVE-2021-44709",
    "CVE-2021-44710",
    "CVE-2021-44711",
    "CVE-2021-44712",
    "CVE-2021-44713",
    "CVE-2021-44714",
    "CVE-2021-44715",
    "CVE-2021-44739",
    "CVE-2021-44740",
    "CVE-2021-44741",
    "CVE-2021-44742",
    "CVE-2021-45060",
    "CVE-2021-45061",
    "CVE-2021-45062",
    "CVE-2021-45063",
    "CVE-2021-45064",
    "CVE-2021-45067",
    "CVE-2021-45068"
  );
  script_xref(name:"IAVA", value:"2022-A-0013-S");

  script_name(english:"Adobe Reader < 17.011.30207 / 20.004.30020 / 21.011.20039 Multiple Vulnerabilities (APSB22-01) (macOS)");

  script_set_attribute(attribute:"synopsis", value:
"The version of Adobe Reader installed on the remote macOS host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Adobe Reader installed on the remote macOS host is a version prior to 17.011.30207, 20.004.30020, or
21.011.20039. It is, therefore, affected by multiple vulnerabilities.

  - Acrobat Reader DC version 21.007.20099 (and earlier), 20.004.30017 (and earlier) and 17.011.30204 (and
    earlier) are affected by a use-after-free vulnerability in the processing of Format event actions that
    could result in arbitrary code execution in the context of the current user. Exploitation of this issue
    requires user interaction in that a victim must open a malicious file. (CVE-2021-44701, CVE-2021-44704,
    CVE-2021-44705, CVE-2021-44706, CVE-2021-44710, CVE-2021-45062, CVE-2021-45064)

  - Acrobat Reader DC ActiveX Control versions 21.007.20099 (and earlier), 20.004.30017 (and earlier) and
    17.011.30204 (and earlier) are affected by an Information Disclosure vulnerability. An unauthenticated
    attacker could leverage this vulnerability to obtain NTLMv2 credentials. Exploitation of this issue
    requires user interaction in that a victim must visit an attacker controlled web page. (CVE-2021-44702)

  - Acrobat Reader DC version 21.007.20099 (and earlier), 20.004.30017 (and earlier) and 17.011.30204 (and
    earlier) are affected by a stack buffer overflow vulnerability due to insecure handling of a crafted file,
    potentially resulting in arbitrary code execution in the context of the current user. Exploitation of this
    issue requires user interaction in that a victim must open a malicious file. (CVE-2021-44703)

  - Acrobat Reader DC version 21.007.20099 (and earlier), 20.004.30017 (and earlier) and 17.011.30204 (and
    earlier) are affected by an out-of-bounds write vulnerability that could result in arbitrary code
    execution in the context of the current user. Exploitation of this issue requires user interaction in that
    a victim must open a malicious file. (CVE-2021-44707, CVE-2021-45061, CVE-2021-45068)

  - Acrobat Reader DC version 21.007.20099 (and earlier), 20.004.30017 (and earlier) and 17.011.30204 (and
    earlier) are affected by a heap overflow vulnerability due to insecure handling of a crafted file,
    potentially resulting in arbitrary code execution in the context of the current user. Exploitation of this
    issue requires user interaction in that a victim must open a malicious file. (CVE-2021-44708,
    CVE-2021-44709)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://cwe.mitre.org/data/definitions/20.html");
  script_set_attribute(attribute:"see_also", value:"https://cwe.mitre.org/data/definitions/121.html");
  script_set_attribute(attribute:"see_also", value:"https://cwe.mitre.org/data/definitions/122.html");
  script_set_attribute(attribute:"see_also", value:"https://cwe.mitre.org/data/definitions/125.html");
  script_set_attribute(attribute:"see_also", value:"https://cwe.mitre.org/data/definitions/190.html");
  script_set_attribute(attribute:"see_also", value:"https://cwe.mitre.org/data/definitions/284.html");
  script_set_attribute(attribute:"see_also", value:"https://cwe.mitre.org/data/definitions/416.html");
  script_set_attribute(attribute:"see_also", value:"https://cwe.mitre.org/data/definitions/476.html");
  script_set_attribute(attribute:"see_also", value:"https://cwe.mitre.org/data/definitions/657.html");
  script_set_attribute(attribute:"see_also", value:"https://cwe.mitre.org/data/definitions/787.html");
  script_set_attribute(attribute:"see_also", value:"https://cwe.mitre.org/data/definitions/788.html");
  script_set_attribute(attribute:"see_also", value:"https://cwe.mitre.org/data/definitions/824.html");
  script_set_attribute(attribute:"see_also", value:"https://helpx.adobe.com/security/products/acrobat/apsb22-01.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Adobe Reader version 17.011.30207 / 20.004.30020 / 21.011.20039 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-45062");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2021-45068");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_cwe_id(20, 121, 122, 125, 190, 284, 416, 476, 657, 787, 788, 824);

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/01/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/01/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/01/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:acrobat_reader");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("macosx_adobe_reader_installed.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/MacOSX/Version", "installed_sw/Adobe Reader");

  exit(0);
}

include('vcf.inc');
include('vcf_extras.inc');

get_kb_item_or_exit('Host/local_checks_enabled');
os = get_kb_item('Host/MacOSX/Version');
if (empty_or_null(os)) audit(AUDIT_OS_NOT, 'Mac OS X');

var app_info = vcf::get_app_info(app:'Adobe Reader');

# vcf::adobe_reader::check_version_and_report will
# properly separate tracks when checking constraints.
# x.y.30zzz = DC Classic
# x.y.20zzz = DC Continuous
var constraints = [
  { 'min_version' : '15.7', 'max_version' : '21.007.20099', 'fixed_version' : '21.011.20039' },
  { 'min_version' : '20.1', 'max_version' : '20.004.30017', 'fixed_version' : '20.004.30020' },
  { 'min_version' : '17.8', 'max_version' : '17.011.30204', 'fixed_version' : '17.011.30207' }
];
vcf::adobe_reader::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE, max_segs:3);
