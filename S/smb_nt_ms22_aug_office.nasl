##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(163950);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/07");

  script_cve_id("CVE-2022-34717");
  script_xref(name:"MSKB", value:"4462148");
  script_xref(name:"MSKB", value:"4462142");
  script_xref(name:"MSFT", value:"MS22-4462148");
  script_xref(name:"MSFT", value:"MS22-4462142");
  script_xref(name:"IAVA", value:"2022-A-0316-S");

  script_name(english:"Security Updates for Microsoft Office Products (August 2022)");

  script_set_attribute(attribute:"synopsis", value:
"The Microsoft Office Products are affected by a remote code execution vulnerability.");
  script_set_attribute(attribute:"description", value:
"The Microsoft Office Products are missing security updates. It is, therefore, affected by the following vulnerability:

  - A remote code execution vulnerability. An attacker can exploit this to bypass authentication and execute
    unauthorized arbitrary commands. (CVE-2022-34717)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/4462148");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/4462142");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released the following security updates to address this issue:  
  -KB4462148
  -KB4462142

For Office 365, Office 2016 C2R, or Office 2019, ensure automatic
updates are enabled or open any office app and manually perform an
update.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-34717");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/08/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/08/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/08/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:office");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("office_installed.nasl", "smb_hotfixes.nasl", "ms_bulletin_checks_possible.nasl");
  script_require_keys("SMB/MS_Bulletin_Checks/Possible");
  script_require_ports(139, 445, "Host/patch_management_checks");

  exit(0);
}

include('vcf_extras_office.inc');

var bulletin = 'MS22-08';
var kbs = make_list(
  '4462142',
  '4462148'
);
var severity = SECURITY_HOLE;

var app_info = vcf::microsoft::office::get_app_info(app:'Microsoft Office', kbs:kbs, bulletin:bulletin, severity:severity);

var constraints = [
  {'product' : 'Microsoft Office 2013 SP1', 'kb':'4462142', 'file':'msohev.dll', 'fixed_version': '15.0.5475.1000'},
  {'product' : 'Microsoft Office 2016', 'kb':'4462148', 'file':'msohev.dll', 'fixed_version': '16.0.5356.1000'}
];

vcf::microsoft::office::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:severity,
  bulletin:bulletin,
  subproduct:'Office'
);
