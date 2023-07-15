#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(167117);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/29");
  script_xref(name:"MSKB", value:"3191875");
  script_xref(name:"MSKB", value:"3191869");
  script_xref(name:"MSFT", value:"MS22-3191875");
  script_xref(name:"MSFT", value:"MS22-3191869");
  script_xref(name:"IAVA", value:"2022-A-0479-S");

  script_name(english:"Security Updates for Microsoft Office Products (November 2022)");

  script_set_attribute(attribute:"synopsis", value:
"The Microsoft Office Products are missing a security update.");
  script_set_attribute(attribute:"description", value:
"The Microsoft Office Products are missing a security update that provides enhanced security as a defense-in-depth
measure. This update provides hardening around IRM-protected documents to ensure the trust-of-certificate chain.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/3191875");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/3191869");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/ADV220003");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released the following security updates to address this issue:  
  -KB3191875
  -KB3191869

For Office 365, Office 2016 C2R, or Office 2019, ensure automatic updates are enabled or open any office app and
manually perform an update.");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/11/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/11/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/11/08");

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

var bulletin = 'MS22-11';
var kbs = make_list(
  '3191869',
  '3191875'
);
var severity = SECURITY_NOTE;

var app_info = vcf::microsoft::office::get_app_info(app:'Microsoft Office', kbs:kbs, bulletin:bulletin, severity:severity);

# Due to first segment of fixed version being the same, this is needed to distinguish the products
var office_vers = hotfix_check_office_version();

var product, kb;
var office_sp_2013 = get_kb_item('SMB/Office/2013/SP');
var office_sp_2016 = get_kb_item('SMB/Office/2016/SP');

if (office_vers['15.0'] && !empty_or_null(office_sp_2013) && office_sp_2013 == 1)
{
  product = 'Microsoft Office 2013 SP1';
  kb = '3191875';
}
else if (office_vers['16.0'] && !empty_or_null(office_sp_2016) && office_sp_2016 == 0)
{
  product = 'Microsoft Office 2016';
  kb = '3191869';
}
else
  audit(AUDIT_HOST_NOT, 'affected');

var constraints = [
  {'product' : product, 'kb':kb, 'file':'msipc.dll', 'fixed_version': '1.0.5017.0'}
];

vcf::microsoft::office::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:severity,
  bulletin:bulletin,
  subproduct:'Office'
);
