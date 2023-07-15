#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(153363);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/01/26");

  script_cve_id(
    "CVE-2021-35982",
    "CVE-2021-39836",
    "CVE-2021-39837",
    "CVE-2021-39838",
    "CVE-2021-39839",
    "CVE-2021-39840",
    "CVE-2021-39841",
    "CVE-2021-39842",
    "CVE-2021-39843",
    "CVE-2021-39844",
    "CVE-2021-39845",
    "CVE-2021-39846",
    "CVE-2021-39849",
    "CVE-2021-39850",
    "CVE-2021-39851",
    "CVE-2021-39852",
    "CVE-2021-39853",
    "CVE-2021-39854",
    "CVE-2021-39855",
    "CVE-2021-39856",
    "CVE-2021-39857",
    "CVE-2021-39858",
    "CVE-2021-39859",
    "CVE-2021-39860",
    "CVE-2021-39861",
    "CVE-2021-39863"
  );
  script_xref(name:"IAVA", value:"2021-A-0415-S");

  script_name(english:"Adobe Acrobat < 2017.011.30202 / 2020.004.30015 / 2021.007.20091 Multiple Vulnerabilities (APSB21-55)");

  script_set_attribute(attribute:"synopsis", value:
"The version of Adobe Acrobat installed on the remote Windows host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Adobe Acrobat installed on the remote Windows host is a version prior to 2017.011.30202, 2020.004.30015,
or 2021.007.20091. It is, therefore, affected by multiple vulnerabilities.

  - Acrobat Reader DC versions 2021.005.20060 (and earlier), 2020.004.30006 (and earlier) and 2017.011.30199
    (and earlier) are affected by a Buffer Overflow vulnerability when parsing a specially crafted PDF file.
    An unauthenticated attacker could leverage this vulnerability to achieve arbitrary code execution in the
    context of the current user. Exploitation of this issue requires user interaction in that a victim must
    open a malicious file. (CVE-2021-39863)

  - Acrobat Reader DC versions 2021.005.20060 (and earlier), 2020.004.30006 (and earlier) and 2017.011.30199
    (and earlier) are affected by an Uncontrolled Search Path Element vulnerability. An attacker could
    leverage this vulnerability to achieve arbitrary code execution in the context of the current user via DLL
    hijacking. Exploitation of this issue requires user interaction. (CVE-2021-35982)

  - Acrobat Reader DC versions 2021.005.20060 (and earlier), 2020.004.30006 (and earlier) and 2017.011.30199
    (and earlier) are affected by a use-after-free vulnerability in the processing of the AcroForm
    buttonGetIcon action that could result in arbitrary code execution in the context of the current user.
    Exploitation of this issue requires user interaction in that a victim must open a malicious file.
    (CVE-2021-39836)

  - Acrobat Reader DC versions 2021.005.20060 (and earlier), 2020.004.30006 (and earlier) and 2017.011.30199
    (and earlier) are affected by a use-after-free vulnerability in the processing of the AcroForm
    deleteItemAt action that could result in arbitrary code execution in the context of the current user.
    Exploitation of this issue requires user interaction in that a victim must open a malicious file.
    (CVE-2021-39837)

  - Acrobat Reader DC versions 2021.005.20060 (and earlier), 2020.004.30006 (and earlier) and 2017.011.30199
    (and earlier) are affected by a use-after-free vulnerability in the processing of the AcroForm
    buttonGetCaption action that could result in arbitrary code execution in the context of the current user.
    Exploitation of this issue requires user interaction in that a victim must open a malicious file.
    (CVE-2021-39838)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://cwe.mitre.org/data/definitions/121.html");
  script_set_attribute(attribute:"see_also", value:"https://cwe.mitre.org/data/definitions/122.html");
  script_set_attribute(attribute:"see_also", value:"https://cwe.mitre.org/data/definitions/125.html");
  script_set_attribute(attribute:"see_also", value:"https://cwe.mitre.org/data/definitions/200.html");
  script_set_attribute(attribute:"see_also", value:"https://cwe.mitre.org/data/definitions/416.html");
  script_set_attribute(attribute:"see_also", value:"https://cwe.mitre.org/data/definitions/427.html");
  script_set_attribute(attribute:"see_also", value:"https://cwe.mitre.org/data/definitions/476.html");
  script_set_attribute(attribute:"see_also", value:"https://cwe.mitre.org/data/definitions/787.html");
  script_set_attribute(attribute:"see_also", value:"https://cwe.mitre.org/data/definitions/843.html");
  script_set_attribute(attribute:"see_also", value:"https://helpx.adobe.com/security/products/acrobat/apsb21-55.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Adobe Acrobat version 2017.011.30202 / 2020.004.30015 / 2021.007.20091 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-39863");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(121, 122, 125, 200, 416, 427, 476, 787, 843);

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/09/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/09/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/09/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:acrobat");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2021-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("adobe_acrobat_installed.nasl");
  script_require_keys("SMB/Registry/Enumerated", "installed_sw/Adobe Acrobat");

  exit(0);
}

include('vcf.inc');
include('vcf_extras.inc');

get_kb_item_or_exit('SMB/Registry/Enumerated');
var app_info = vcf::get_app_info(app:'Adobe Acrobat', win_local:TRUE);

# vcf::adobe_reader::check_version_and_report will
# properly separate tracks when checking constraints.
# x.y.30zzz = DC Classic
# x.y.20zzz = DC Continuous
var constraints = [
  { 'min_version' : '15.7', 'max_version' : '21.005.20060', 'fixed_version' : '21.007.20091' },
  { 'min_version' : '20.1', 'max_version' : '20.004.30006', 'fixed_version' : '20.004.30015' },
  { 'min_version' : '17.8', 'max_version' : '17.011.30199', 'fixed_version' : '17.011.30202' }
];
vcf::adobe_reader::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING, max_segs:3);
