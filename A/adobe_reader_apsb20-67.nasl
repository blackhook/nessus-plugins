##
# (C) Tenable Network Security, Inc.
##

include('compat.inc');

if (description)
{
  script_id(142467);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/02/25");

  script_cve_id(
    "CVE-2020-24426",
    "CVE-2020-24427",
    "CVE-2020-24428",
    "CVE-2020-24429",
    "CVE-2020-24430",
    "CVE-2020-24431",
    "CVE-2020-24432",
    "CVE-2020-24433",
    "CVE-2020-24434",
    "CVE-2020-24435",
    "CVE-2020-24436",
    "CVE-2020-24437",
    "CVE-2020-24438",
    "CVE-2020-24439"
  );
  script_xref(name:"IAVA", value:"2020-A-0506-S");

  script_name(english:"Adobe Reader <= 2017.011.30175 / 2020.001.30005 / 2020.012.20048 Multiple Vulnerabilities (APSB20-67)");

  script_set_attribute(attribute:"synopsis", value:
"The version of Adobe Reader installed on the remote Windows host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Adobe Reader installed on the remote Windows host is a version prior or equal to 2017.011.30175,
2020.001.30005, or 2020.012.20048. It is, therefore, affected by multiple vulnerabilities.

  - Acrobat Reader DC versions 2020.012.20048 (and earlier), 2020.001.30005 (and earlier) and 2017.011.30175
    (and earlier) are affected by an out-of-bounds read vulnerability that could lead to disclosure of
    sensitive memory. An attacker could leverage this vulnerability to bypass mitigations such as ASLR.
    Exploitation of this issue requires user interaction in that a victim must open a malicious file.
    (CVE-2020-24426, CVE-2020-24434)

  - Acrobat Reader versions 2020.012.20048 (and earlier), 2020.001.30005 (and earlier) and 2017.011.30175 (and
    earlier) are affected by an input validation vulnerability when decoding a crafted codec that could result
    in the disclosure of sensitive memory. An attacker could leverage this vulnerability to bypass mitigations
    such as ASLR. Exploitation of this issue requires user interaction in that a victim must open a malicious
    file. (CVE-2020-24427)

  - Acrobat Reader DC versions 2020.012.20048 (and earlier), 2020.001.30005 (and earlier) and 2017.011.30175
    (and earlier) for macOS are affected by a time-of-check time-of-use (TOCTOU) race condition vulnerability
    that could result in local privilege escalation. Exploitation of this issue requires user interaction in
    that a victim must open a malicious file. (CVE-2020-24428)

  - Acrobat Reader DC versions 2020.012.20048 (and earlier), 2020.001.30005 (and earlier) and 2017.011.30175
    (and earlier) for macOS are affected by a signature verification bypass that could result in local
    privilege escalation. Exploitation of this issue requires user interaction in that a victim must open a
    malicious file. (CVE-2020-24429)

  - Acrobat Reader DC versions 2020.012.20048 (and earlier), 2020.001.30005 (and earlier) and 2017.011.30175
    (and earlier) are affected by a use-after-free vulnerability when handling malicious JavaScript. This
    vulnerability could result in arbitrary code execution in the context of the current user. Exploitation
    requires user interaction in that a victim must open a malicious file. (CVE-2020-24430)

  - Acrobat Reader DC versions 2020.012.20048 (and earlier), 2020.001.30005 (and earlier) and 2017.011.30175
    (and earlier) for macOS are affected by a security feature bypass that could result in dynamic library
    code injection by the Adobe Reader process. Exploitation of this issue requires user interaction in that a
    victim must open a malicious file. (CVE-2020-24431)

  - Acrobat Reader DC versions 2020.012.20048 (and earlier), 2020.001.30005 (and earlier) and 2017.011.30175
    (and earlier) and Adobe Acrobat Pro DC 2017.011.30175 (and earlier) are affected by an improper input
    validation vulnerability that could result in arbitrary JavaScript execution in the context of the current
    user. To exploit this issue, an attacker must acquire and then modify a certified PDF document that is
    trusted by the victim. The attacker then needs to convince the victim to open the document.
    (CVE-2020-24432)

  - Adobe Acrobat Reader DC versions 2020.012.20048 (and earlier), 2020.001.30005 (and earlier) and
    2017.011.30175 (and earlier) are affected by a local privilege escalation vulnerability that could enable
    a user without administrator privileges to delete arbitrary files and potentially execute arbitrary code
    as SYSTEM. Exploitation of this issue requires an attacker to socially engineer a victim, or the attacker
    must already have some access to the environment. (CVE-2020-24433)

  - Acrobat Reader DC versions 2020.012.20048 (and earlier), 2020.001.30005 (and earlier) and 2017.011.30175
    (and earlier) are affected by a heap-based buffer overflow vulnerability in the submitForm function,
    potentially resulting in arbitrary code execution in the context of the current user. Exploitation
    requires user interaction in that a victim must open a crafted .pdf file in Acrobat Reader.
    (CVE-2020-24435)

  - Acrobat Pro DC versions 2020.012.20048 (and earlier), 2020.001.30005 (and earlier) and 2017.011.30175 (and
    earlier) are affected by an out-of-bounds write vulnerability that could result in writing past the end of
    an allocated memory structure. An attacker could leverage this vulnerability to execute code in the
    context of the current user. This vulnerability requires user interaction to exploit in that the victim
    must open a malicious document. (CVE-2020-24436)

  - Acrobat Reader DC versions 2020.012.20048 (and earlier), 2020.001.30005 (and earlier) and 2017.011.30175
    (and earlier) are affected by a use-after-free vulnerability in the processing of Format event actions
    that could result in arbitrary code execution in the context of the current user. Exploitation of this
    issue requires user interaction in that a victim must open a malicious file. (CVE-2020-24437)

  - Acrobat Reader DC versions 2020.012.20048 (and earlier), 2020.001.30005 (and earlier) and 2017.011.30175
    (and earlier) are affected by a use-after-free vulnerability that could result in a memory address leak.
    Exploitation of this issue requires user interaction in that a victim must open a malicious file.
    (CVE-2020-24438)

  - Acrobat Reader DC for macOS versions 2020.012.20048 (and earlier), 2020.001.30005 (and earlier) and
    2017.011.30175 (and earlier) are affected by a security feature bypass. While the practical security
    impact is minimal, a defense-in-depth fix has been implemented to further harden the Adobe Reader update
    process. (CVE-2020-24439)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://helpx.adobe.com/security/products/acrobat/apsb20-67.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Adobe Reader version 2017.011.30175 / 2020.001.30005 / 2020.012.20048 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-24433");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/11/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/11/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/11/05");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:acrobat_reader");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2020-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("adobe_reader_installed.nasl");
  script_require_keys("SMB/Registry/Enumerated", "installed_sw/Adobe Reader");

  exit(0);
}

include('vcf.inc');
include('vcf_extras.inc');

get_kb_item_or_exit('SMB/Registry/Enumerated');
app_info = vcf::get_app_info(app:'Adobe Reader', win_local:TRUE);

# vcf::adobe_reader::check_version_and_report will
# properly separate tracks when checking constraints.
# x.y.30zzz = DC Classic
# x.y.20zzz = DC Continuous
constraints = [
  { 'min_version' : '15.7', 'max_version' : '20.012.20048', 'fixed_version' : '20.013.20064' },
  { 'min_version' : '20.1', 'max_version' : '20.001.30005', 'fixed_version' : '20.001.30010' },
  { 'min_version' : '17.8', 'max_version' : '17.011.30175', 'fixed_version' : '17.011.30180' }
];
vcf::adobe_reader::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE, max_segs:3);
