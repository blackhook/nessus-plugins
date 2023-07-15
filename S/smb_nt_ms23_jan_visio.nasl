#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(169780);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/01/13");

  script_cve_id("CVE-2023-21736", "CVE-2023-21737", "CVE-2023-21741");
  script_xref(name:"MSKB", value:"5002332");
  script_xref(name:"MSKB", value:"5002337");
  script_xref(name:"MSFT", value:"MS23-5002332");
  script_xref(name:"MSFT", value:"MS23-5002337");
  script_xref(name:"IAVA", value:"2023-A-0030");

  script_name(english:"Security Updates for Microsoft Visio Products (January 2023)");

  script_set_attribute(attribute:"synopsis", value:
"The Microsoft Visio Products are affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The Microsoft Visio Products are missing security updates. It is, therefore, affected by multiple vulnerabilities:

  - A remote code execution vulnerability. An attacker can exploit this to bypass authentication and execute
    unauthorized arbitrary commands. (CVE-2023-21736, CVE-2023-21737)

  - An information disclosure vulnerability. An attacker can exploit this to disclose potentially sensitive
    information. (CVE-2023-21741)");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5002332");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5002337");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released the following security updates to address this issue:  
  -KB5002337
  -KB5002332");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-21741");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2023-21737");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/01/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/01/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/01/10");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:visio");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("office_installed.nasl", "microsoft_visio_installed.nbin", "smb_hotfixes.nasl", "ms_bulletin_checks_possible.nasl");
  script_require_keys("SMB/MS_Bulletin_Checks/Possible");
  script_require_ports(139, 445, "Host/patch_management_checks");

  exit(0);
}

include('vcf_extras_office.inc');

var bulletin = 'MS23-01';
var kbs = make_list(
  '5002332',
  '5002337'
);

var constraints = [
  { 'kb':'5002332',  'fixed_version': '15.0.5519.1000', 'sp' : 1},
  { 'kb':'5002337', 'channel':'MSI', 'fixed_version': '16.0.5378.1000', 'sp' : 0}
];

vcf::microsoft::office_product::check_version_and_report(
  kbs:kbs,
  constraints:constraints,
  severity:SECURITY_HOLE,
  bulletin:bulletin,
  subproduct:'Visio'
);
