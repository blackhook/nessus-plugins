#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(156662);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/06/20");

  script_cve_id(
    "CVE-2021-44185",
    "CVE-2021-44186",
    "CVE-2021-44187",
    "CVE-2021-44743",
    "CVE-2021-45051",
    "CVE-2021-45052"
  );
  script_xref(name:"IAVA", value:"2022-A-0015-S");

  script_name(english:"Adobe Bridge 11.x < 11.1.3 / 12.x < 12.0.1 Multiple Vulnerabilities (APSB22-03)");

  script_set_attribute(attribute:"synopsis", value:
"Adobe Bridge installed on remote macOS or Mac OS X host is affected by a multiple vulnerabilities");
  script_set_attribute(attribute:"description", value:
"The version of Adobe Bridge installed on the remote macOS or Mac OS X host is prior to 12.0.1 or 11.1.3. It is,
therefore, affected by multiple vulnerabilities as referenced in the apsb22-03 advisory.

  - Adobe Bridge version 11.1.2 (and earlier) and version 12.0 (and earlier) are affected by an out-of-bounds
    write vulnerability that could result in arbitrary code execution in the context of the current user.
    Exploitation of this issue requires user interaction in that a victim must open a malicious file.
    (CVE-2021-44743)

  - Adobe Bridge version 11.1.2 (and earlier) and version 12.0 (and earlier) are affected by an out-of-bounds
    read vulnerability that could lead to disclosure of sensitive memory. An attacker could leverage this
    vulnerability to bypass mitigations such as ASLR. Exploitation of this issue requires user interaction in
    that a victim must open a malicious RGB file. (CVE-2021-44185)

  - Adobe Bridge version 11.1.2 (and earlier) and version 12.0 (and earlier) are affected by an out-of-bounds
    read vulnerability that could lead to disclosure of sensitive memory. An attacker could leverage this
    vulnerability to bypass mitigations such as ASLR. Exploitation of this issue requires user interaction in
    that a victim must open a malicious SGI file. (CVE-2021-44186, CVE-2021-44187)

  - Adobe Bridge version 11.1.2 (and earlier) and version 12.0 (and earlier) are affected by an use-after-free
    vulnerability in the processing of Format event actions that could lead to disclosure of sensitive memory.
    An attacker could leverage this vulnerability to bypass mitigations such as ASLR. Exploitation of this
    issue requires user interaction in that a victim must open a malicious file. (CVE-2021-45051)

  - Adobe Bridge version 11.1.2 (and earlier) and version 12.0 (and earlier) are affected by an out-of-bounds
    read vulnerability that could lead to disclosure of sensitive memory. An attacker could leverage this
    vulnerability to bypass mitigations such as ASLR. Exploitation of this issue requires user interaction in
    that a victim must open a malicious TIF file. (CVE-2021-45052)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://cwe.mitre.org/data/definitions/125.html");
  script_set_attribute(attribute:"see_also", value:"https://cwe.mitre.org/data/definitions/416.html");
  script_set_attribute(attribute:"see_also", value:"https://cwe.mitre.org/data/definitions/787.html");
  script_set_attribute(attribute:"see_also", value:"https://helpx.adobe.com/security/products/bridge/apsb22-03.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Adobe Bridge version 12.0.1 or 11.1.3 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-44743");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(125, 416, 787);

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/12/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/01/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/01/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:bridge");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("macosx_adobe_bridge_installed.nbin");
  script_require_keys("Host/local_checks_enabled", "Host/MacOSX/Version", "installed_sw/Adobe Bridge");

  exit(0);
}

include('vcf.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

get_kb_item_or_exit('Host/MacOSX/Version');

var app_info = vcf::get_app_info(app:'Adobe Bridge');

var constraints = [
  { 'min_version' : '11.0.0', 'fixed_version' : '11.1.3' },
  { 'min_version' : '12.0.0', 'fixed_version' : '12.0.1' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
