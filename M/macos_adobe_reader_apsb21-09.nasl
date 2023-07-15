##
# (C) Tenable Network Security, Inc.
##

include('compat.inc');

if (description)
{
  script_id(146423);
  script_version("1.16");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/25");

  script_cve_id(
    "CVE-2021-21017",
    "CVE-2021-21021",
    "CVE-2021-21028",
    "CVE-2021-21033",
    "CVE-2021-21034",
    "CVE-2021-21035",
    "CVE-2021-21036",
    "CVE-2021-21037",
    "CVE-2021-21038",
    "CVE-2021-21039",
    "CVE-2021-21040",
    "CVE-2021-21041",
    "CVE-2021-21042",
    "CVE-2021-21044",
    "CVE-2021-21045",
    "CVE-2021-21046",
    "CVE-2021-21057",
    "CVE-2021-21058",
    "CVE-2021-21059",
    "CVE-2021-21060",
    "CVE-2021-21061",
    "CVE-2021-21062",
    "CVE-2021-21063",
    "CVE-2021-21088",
    "CVE-2021-21089",
    "CVE-2021-40723"
  );
  script_xref(name:"IAVA", value:"2021-A-0092-S");
  script_xref(name:"IAVA", value:"2021-A-0157-S");
  script_xref(name:"IAVA", value:"2021-A-0229-S");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2021/11/17");

  script_name(english:"Adobe Reader <= 2017.011.30188 / 2020.001.30018 / 2020.013.20074 Multiple Vulnerabilities (APSB21-09) (macOS)");

  script_set_attribute(attribute:"synopsis", value:
"The version of Adobe Reader installed on the remote macOS host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Adobe Reader installed on the remote macOS host is a version prior or equal to 2017.011.30188,
2020.001.30018, or 2020.013.20074. It is, therefore, affected by multiple vulnerabilities.

  - Acrobat Reader DC versions versions 2020.013.20074 (and earlier), 2020.001.30018 (and earlier) and
    2017.011.30188 (and earlier) are affected by a heap-based buffer overflow vulnerability. An
    unauthenticated attacker could leverage this vulnerability to achieve arbitrary code execution in the
    context of the current user. Exploitation of this issue requires user interaction in that a victim must
    open a malicious file. (CVE-2021-21017)

  - Acrobat Reader DC versions versions 2020.013.20074 (and earlier), 2020.001.30018 (and earlier) and
    2017.011.30188 (and earlier) are affected by a Use After Free vulnerability. An unauthenticated attacker
    could leverage this vulnerability to achieve arbitrary code execution in the context of the current user.
    Exploitation of this issue requires user interaction in that a victim must open a malicious file.
    (CVE-2021-21021, CVE-2021-21028, CVE-2021-21033, CVE-2021-21035, CVE-2021-21039, CVE-2021-21040)

  - Acrobat Reader DC versions versions 2020.013.20074 (and earlier), 2020.001.30018 (and earlier) and
    2017.011.30188 (and earlier) are affected by an Out-of-bounds Read vulnerability. An unauthenticated
    attacker could leverage this vulnerability to locally elevate privileges in the context of the current
    user. Exploitation of this issue requires user interaction in that a victim must open a malicious file.
    (CVE-2021-21034)

  - Acrobat Reader DC versions versions 2020.013.20074 (and earlier), 2020.001.30018 (and earlier) and
    2017.011.30188 (and earlier) are affected by an Integer Overflow vulnerability. An unauthenticated
    attacker could leverage this vulnerability to achieve arbitrary code execution in the context of the
    current user. Exploitation of this issue requires user interaction in that a victim must open a malicious
    file. (CVE-2021-21036)

  - Acrobat Reader DC versions versions 2020.013.20074 (and earlier), 2020.001.30018 (and earlier) and
    2017.011.30188 (and earlier) are affected by a Path Traversal vulnerability. An unauthenticated attacker
    could leverage this vulnerability to achieve arbitrary code execution in the context of the current user.
    Exploitation of this issue requires user interaction in that a victim must open a malicious file.
    (CVE-2021-21037)

  - Acrobat Reader DC versions versions 2020.013.20074 (and earlier), 2020.001.30018 (and earlier) and
    2017.011.30188 (and earlier) are affected by an Out-of-bounds Write vulnerability when parsing a crafted
    jpeg file. An unauthenticated attacker could leverage this vulnerability to achieve arbitrary code
    execution in the context of the current user. Exploitation of this issue requires user interaction in that
    a victim must open a malicious file. (CVE-2021-21038, CVE-2021-21044)

  - Acrobat Reader DC versions versions 2020.013.20074 (and earlier), 2020.001.30018 (and earlier) and
    2017.011.30188 (and earlier) are affected by a use-after-free vulnerability. An unauthenticated attacker
    could leverage this vulnerability to achieve arbitrary code execution in the context of the current user.
    Exploitation of this issue requires user interaction in that a victim must open a malicious file.
    (CVE-2021-21041)

  - Acrobat Reader DC versions versions 2020.013.20074 (and earlier), 2020.001.30018 (and earlier) and
    2017.011.30188 (and earlier) are affected by an Out-of-bounds Read vulnerability. An unauthenticated
    attacker could leverage this vulnerability to locally escalate privileges in the context of the current
    user. Exploitation of this issue requires user interaction in that a victim must open a malicious file.
    (CVE-2021-21042)

  - Acrobat Reader DC versions versions 2020.013.20074 (and earlier), 2020.001.30018 (and earlier) and
    2017.011.30188 (and earlier) are affected by an improper access control vulnerability. An unauthenticated
    attacker could leverage this vulnerability to elevate privileges in the context of the current user.
    (CVE-2021-21045)

  - Acrobat Reader DC versions versions 2020.013.20074 (and earlier), 2020.001.30018 (and earlier) and
    2017.011.30188 (and earlier) are affected by an memory corruption vulnerability. An unauthenticated
    attacker could leverage this vulnerability to cause an application denial-of-service. Exploitation of this
    issue requires user interaction in that a victim must open a malicious file. (CVE-2021-21046)

  - Acrobat Reader DC versions versions 2020.013.20074 (and earlier), 2020.001.30018 (and earlier) and
    2017.011.30188 (and earlier) are affected by a null pointer dereference vulnerability when parsing a
    specially crafted PDF file. An unauthenticated attacker could leverage this vulnerability to achieve
    denial of service in the context of the current user. Exploitation of this issue requires user interaction
    in that a victim must open a malicious file. (CVE-2021-21057)

  - Acrobat Reader DC versions versions 2020.013.20074 (and earlier), 2020.001.30018 (and earlier) and
    2017.011.30188 (and earlier) are affected by a Memory corruption vulnerability when parsing a specially
    crafted PDF file. An unauthenticated attacker could leverage this vulnerability to achieve arbitrary code
    execution in the context of the current user. Exploitation of this issue requires user interaction in that
    a victim must open a malicious file. (CVE-2021-21058, CVE-2021-21059, CVE-2021-21062, CVE-2021-21063)

  - Adobe Acrobat Pro DC versions 2020.013.20074 (and earlier), 2020.001.30018 (and earlier) and
    2017.011.30188 (and earlier) are affected by an improper input validation vulnerability. An
    unauthenticated attacker could leverage this vulnerability to disclose sensitive information in the
    context of the current user. Exploitation of this issue requires user interaction in that a victim must
    open a malicious file. (CVE-2021-21060)

  - Acrobat Pro DC versions versions 2020.013.20074 (and earlier), 2020.001.30018 (and earlier) and
    2017.011.30188 (and earlier) are affected by a Use-after-free vulnerability when parsing a specially
    crafted PDF file. An unauthenticated attacker could leverage this vulnerability to disclose sensitive
    information in the context of the current user. Exploitation of this issue requires user interaction in
    that a victim must open a malicious file. (CVE-2021-21061)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://helpx.adobe.com/security/products/acrobat/apsb21-09.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Adobe Reader version 2017.011.30188 / 2020.001.30018 / 2020.013.20074 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-21063");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2021-21035");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/02/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/02/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/02/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:acrobat_reader");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("macosx_adobe_reader_installed.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/MacOSX/Version", "installed_sw/Adobe Reader");

  exit(0);
}

include('vcf.inc');
include('vcf_extras.inc');

get_kb_item_or_exit('Host/local_checks_enabled');
os = get_kb_item('Host/MacOSX/Version');
if (empty_or_null(os)) audit(AUDIT_OS_NOT, 'Mac OS X');

app_info = vcf::get_app_info(app:'Adobe Reader');

# vcf::adobe_reader::check_version_and_report will
# properly separate tracks when checking constraints.
# x.y.30zzz = DC Classic
# x.y.20zzz = DC Continuous
constraints = [
  { 'min_version' : '15.7', 'max_version' : '20.013.20074', 'fixed_version' : '21.001.20135' },
  { 'min_version' : '20.1', 'max_version' : '20.001.30018', 'fixed_version' : '20.001.30020' },
  { 'min_version' : '17.8', 'max_version' : '17.011.30188', 'fixed_version' : '17.011.30190' }
];
vcf::adobe_reader::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE, max_segs:3);
