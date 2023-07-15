#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(165080);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/02/16");

  script_cve_id(
    "CVE-2022-35699",
    "CVE-2022-35700",
    "CVE-2022-35701",
    "CVE-2022-35702",
    "CVE-2022-35703",
    "CVE-2022-35704",
    "CVE-2022-35705",
    "CVE-2022-35706",
    "CVE-2022-35707",
    "CVE-2022-35708",
    "CVE-2022-35709",
    "CVE-2022-38425"
  );
  script_xref(name:"IAVA", value:"2022-A-0363-S");

  script_name(english:"Adobe Bridge 11.x < 11.1.4 / 12.x < 12.0.3 Multiple Vulnerabilities (APSB22-49)");

  script_set_attribute(attribute:"synopsis", value:
"Adobe Bridge installed on remote macOS or Mac OS X host is affected by a multiple vulnerabilities");
  script_set_attribute(attribute:"description", value:
"The version of Adobe Bridge installed on the remote macOS or Mac OS X host is prior to 12.0.3 or 11.1.4. It is,
therefore, affected by multiple vulnerabilities as referenced in the apsb22-49 advisory.

  - Adobe Bridge version 11.1.2 (and earlier) and version 12.0 (and earlier) are affected by an out-of-bounds
    read vulnerability that could lead to disclosure of sensitive memory. An attacker could leverage this
    vulnerability to bypass mitigations such as ASLR. Exploitation of this issue requires user interaction in
    that a victim must open a malicious RGB file. (CVE-2021-44185)

  - Adobe Bridge version 11.1.2 (and earlier) and version 12.0 (and earlier) are affected by an out-of-bounds
    read vulnerability that could lead to disclosure of sensitive memory. An attacker could leverage this
    vulnerability to bypass mitigations such as ASLR. Exploitation of this issue requires user interaction in
    that a victim must open a malicious SGI file. (CVE-2021-44186, CVE-2021-44187)

  - Out-of-bounds Write (CWE-787) potentially leading to Arbitrary code execution (CVE-2022-35699,
    CVE-2022-35700, CVE-2022-35701)

  - Out-of-bounds Read (CWE-125) potentially leading to Arbitrary code execution (CVE-2022-35702,
    CVE-2022-35703, CVE-2022-35705, CVE-2022-35707)

  - Use After Free (CWE-416) potentially leading to Arbitrary code execution (CVE-2022-35704)

  - Heap-based Buffer Overflow (CWE-122) potentially leading to Arbitrary code execution (CVE-2022-35706,
    CVE-2022-35708)

  - Use After Free (CWE-416) potentially leading to Memory Leak (CVE-2022-35709)

  - Use After Free (CWE-416) potentially leading to Memory leak (CVE-2022-38425)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://helpx.adobe.com/security/products/bridge/apsb22-49.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Adobe Bridge version 12.0.3 or 11.1.4 or later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-35708");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(122, 125, 416, 787);

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/12/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/09/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/09/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:bridge");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("macosx_adobe_bridge_installed.nbin");
  script_require_keys("Host/local_checks_enabled", "Host/MacOSX/Version", "installed_sw/Adobe Bridge");

  exit(0);
}

include('vcf.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

get_kb_item_or_exit('Host/MacOSX/Version');

var app_info = vcf::get_app_info(app:'Adobe Bridge');

var constraints = [
  { 'min_version' : '11.0.0', 'fixed_version' : '11.1.4' },
  { 'min_version' : '12.0.0', 'fixed_version' : '12.0.3' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
