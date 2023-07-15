##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(162180);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/23");

  script_cve_id(
    "CVE-2022-28839",
    "CVE-2022-28840",
    "CVE-2022-28841",
    "CVE-2022-28842",
    "CVE-2022-28843",
    "CVE-2022-28844",
    "CVE-2022-28845",
    "CVE-2022-28846",
    "CVE-2022-28847",
    "CVE-2022-28848",
    "CVE-2022-28849",
    "CVE-2022-28850"
  );
  script_xref(name:"IAVA", value:"2022-A-0242-S");

  script_name(english:"Adobe Bridge 12.x < 12.0.2 Multiple Vulnerabilities (APSB22-25)");

  script_set_attribute(attribute:"synopsis", value:
"Adobe Bridge installed on remote Windows host is affected by a multiple vulnerabilities");
  script_set_attribute(attribute:"description", value:
"The version of Adobe Bridge installed on the remote Windows host is prior to 12.0.2. It is, therefore, affected by
multiple vulnerabilities as referenced in the apsb22-25 advisory.

  - Adobe Bridge version 12.0.1 (and earlier versions) is affected by an out-of-bounds write vulnerability
    that could result in arbitrary code execution in the context of the current user. Exploitation of this
    issue requires user interaction in that a victim must open a malicious file. (CVE-2022-28839,
    CVE-2022-28840, CVE-2022-28841, CVE-2022-28843, CVE-2022-28844, CVE-2022-28845, CVE-2022-28846,
    CVE-2022-28847, CVE-2022-28848)

  - Adobe Bridge version 12.0.1 (and earlier versions) is affected by a Use-After-Free vulnerability that
    could result in arbitrary code execution in the context of the current user. Exploitation of this issue
    requires user interaction in that a victim must open a malicious file. (CVE-2022-28842, CVE-2022-28849)

  - Adobe Bridge version 12.0.1 (and earlier versions) is affected by an out-of-bounds read vulnerability that
    could lead to disclosure of sensitive memory. An attacker could leverage this vulnerability to bypass
    mitigations such as ASLR. Exploitation of this issue requires user interaction in that a victim must open
    a malicious file. (CVE-2022-28850)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://helpx.adobe.com/security/products/bridge/apsb22-25.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Adobe Bridge version 12.0.2 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-28844");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2022-28849");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(20, 125, 416, 787);

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/12/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/06/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/06/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:bridge");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("adobe_bridge_installed.nasl");
  script_require_keys("installed_sw/Adobe Bridge", "SMB/Registry/Enumerated");

  exit(0);
}

include('vcf.inc');

get_kb_item_or_exit('SMB/Registry/Enumerated');

var app_info = vcf::get_app_info(app:'Adobe Bridge', win_local:TRUE);

var constraints = [
  { 'min_version' : '12.0.0', 'fixed_version' : '12.0.2' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
