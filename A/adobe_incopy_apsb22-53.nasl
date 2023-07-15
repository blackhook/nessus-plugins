#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(164983);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/21");

  script_cve_id(
    "CVE-2022-38401",
    "CVE-2022-38402",
    "CVE-2022-38403",
    "CVE-2022-38404",
    "CVE-2022-38405",
    "CVE-2022-38406",
    "CVE-2022-38407"
  );
  script_xref(name:"IAVA", value:"2022-A-0366-S");

  script_name(english:"Adobe InCopy < 16.4.3 / 17.0 < 17.4 Multiple Vulnerabilities (APSB22-53)");

  script_set_attribute(attribute:"synopsis", value:
"The Adobe InCopy instance installed on the remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Adobe InCopy installed on the remote host is prior to 16.4.3, 17.4. It is, therefore, affected by
multiple vulnerabilities as referenced in the APSB22-53 advisory.

  - Adobe InCopy version 17.3 (and earlier) and 16.4.2 (and earlier) are affected by a Heap-based Buffer
    Overflow vulnerability that could result in arbitrary code execution in the context of the current user.
    Exploitation of this issue requires user interaction in that a victim must open a malicious file.
    (CVE-2022-38401, CVE-2022-38402, CVE-2022-38403, CVE-2022-38404, CVE-2022-38405)

  - Adobe InCopy version 17.3 (and earlier) and 16.4.2 (and earlier) are affected by an out-of-bounds read
    vulnerability that could lead to disclosure of sensitive memory. An attacker could leverage this
    vulnerability to bypass mitigations such as ASLR. Exploitation of this issue requires user interaction in
    that a victim must open a malicious file. (CVE-2022-38406, CVE-2022-38407)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://helpx.adobe.com/security/products/incopy/apsb22-53.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Adobe InCopy version 16.4.3, 17.4 or later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-38405");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(122, 125);

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/07/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/09/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/09/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:incopy");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("adobe_incopy_win_installed.nbin", "adobe_incopy_mac_installed.nbin");
  script_require_keys("installed_sw/Adobe InCopy");

  exit(0);
}

include('vcf.inc');

var app = 'Adobe InCopy';
var win_local;

if (!empty_or_null(get_kb_item('SMB/Registry/Enumerated')))
  win_local = TRUE;
else
  win_local = FALSE;

var app_info = vcf::get_app_info(app:app, win_local:win_local);

var constraints = [
  { 'fixed_version' : '16.4.3' },
  { 'min_version' : '17.0', 'fixed_version' : '17.4' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
