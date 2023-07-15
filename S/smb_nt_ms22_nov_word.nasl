#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(167110);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/02/16");

  script_cve_id("CVE-2022-41060", "CVE-2022-41061", "CVE-2022-41103");
  script_xref(name:"MSKB", value:"5002217");
  script_xref(name:"MSKB", value:"5002223");
  script_xref(name:"MSFT", value:"MS22-5002217");
  script_xref(name:"MSFT", value:"MS22-5002223");
  script_xref(name:"IAVA", value:"2022-A-0478-S");

  script_name(english:"Security Updates for Microsoft Word Products (November 2022)");

  script_set_attribute(attribute:"synopsis", value:
"The Microsoft Word Products are affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The Microsoft Word Products are missing security updates. It is, therefore, affected by multiple vulnerabilities:

  - A remote code execution vulnerability. An attacker can exploit this to bypass authentication and execute
    unauthorized arbitrary commands. (CVE-2022-41061)

  - An information disclosure vulnerability. An attacker can exploit this to disclose potentially sensitive
    information. (CVE-2022-41060, CVE-2022-41103)");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5002217");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5002223");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released the following security updates to address this issue:  
  -KB5002217
  -KB5002223

For Office 365, Office 2016 C2R, or Office 2019, ensure automatic
updates are enabled or open any office app and manually perform an
update.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-41061");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/11/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/11/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/11/08");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:word");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("office_installed.nasl", "smb_hotfixes.nasl", "ms_bulletin_checks_possible.nasl");
  script_require_keys("SMB/MS_Bulletin_Checks/Possible");
  script_require_ports(139, 445, "Host/patch_management_checks");

  exit(0);
}

include('vcf_extras_office.inc');

var bulletin = 'MS22-11';
var kbs = make_list(
  '5002217',
  '5002223'
);

var constraints = [
  { 'kb':'5002217',  'fixed_version': '15.0.5501.1000', 'sp' : 1},
  { 'kb':'5002223', 'channel':'MSI', 'fixed_version': '16.0.5369.1000', 'sp' : 0}
];

vcf::microsoft::office_product::check_version_and_report(
  kbs:kbs,
  constraints:constraints,
  severity:SECURITY_HOLE,
  bulletin:bulletin,
  subproduct:'Word'
);
