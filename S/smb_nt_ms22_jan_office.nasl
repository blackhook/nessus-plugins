#%NASL_MIN_LEVEL 70300
##
# (C) Tenable, Inc. 
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(156630);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/06/10");

  script_cve_id("CVE-2022-21840", "CVE-2022-21841");
  script_xref(name:"MSKB", value:"4462205");
  script_xref(name:"MSKB", value:"5002052");
  script_xref(name:"MSKB", value:"5002060");
  script_xref(name:"MSKB", value:"5002064");
  script_xref(name:"MSKB", value:"5002115");
  script_xref(name:"MSKB", value:"5002116");
  script_xref(name:"MSKB", value:"5002119");
  script_xref(name:"MSKB", value:"5002124");
  script_xref(name:"MSFT", value:"MS22-4462205");
  script_xref(name:"MSFT", value:"MS22-5002052");
  script_xref(name:"MSFT", value:"MS22-5002060");
  script_xref(name:"MSFT", value:"MS22-5002064");
  script_xref(name:"MSFT", value:"MS22-5002115");
  script_xref(name:"MSFT", value:"MS22-5002116");
  script_xref(name:"MSFT", value:"MS22-5002119");
  script_xref(name:"MSFT", value:"MS22-5002124");
  script_xref(name:"IAVA", value:"2022-A-0018-S");

  script_name(english:"Security Updates for Microsoft Office Products (January 2022)");

  script_set_attribute(attribute:"synopsis", value:
"The Microsoft Office Products are affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The Microsoft Office Products are missing security updates.
It is, therefore, affected by multiple vulnerabilities:

  - A remote code execution vulnerability. An attacker can
    exploit this to bypass authentication and execute
    unauthorized arbitrary commands. (CVE-2022-21840,
    CVE-2022-21841)");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/4462205");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5002052");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5002060");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5002064");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5002115");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5002116");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5002119");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5002124");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released the following security updates to address this issue:  
  -KB4462205
  -KB5002052
  -KB5002060
  -KB5002064
  -KB5002115
  -KB5002116
  -KB5002119
  -KB5002124

For Office 365, Office 2016 C2R, or Office 2019, ensure automatic
updates are enabled or open any office app and manually perform an
update.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-21841");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2022-21840");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/01/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/01/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/01/11");

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

include('smb_func.inc');
include('smb_hotfixes.inc');
include('smb_hotfixes_fcheck.inc');
include('smb_reg_query.inc');

get_kb_item_or_exit('SMB/MS_Bulletin_Checks/Possible');

var bulletin = 'MS22-01';
var kbs = make_list(
  '4462205',
  '5002052',
  '5002060',
  '5002064',
  '5002115',
  '5002116',
  '5002119',
  '5002124'
);

if (get_kb_item('Host/patch_management_checks'))
  hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

get_kb_item_or_exit('SMB/Registry/Enumerated', exit_code:1);

var vuln = FALSE;
var port = kb_smb_transport();

var office_vers = hotfix_check_office_version();

var office_sp, prod, path, kb, file, version;

# Office 2013 SP1
if (office_vers['15.0'])
{
  office_sp = get_kb_item('SMB/Office/2013/SP');
  if (!isnull(office_sp) && office_sp == 1)
  {
    prod = 'Microsoft Office 2013 SP1';

    path = hotfix_get_officecommonfilesdir(officever:'15.0');
    path = hotfix_append_path(path:path, value:'Microsoft Shared\\Office15');
    kb = '5002124';
    file = 'acecore.dll';
    version = '15.0.5415.1001';
    if (hotfix_check_fversion(file:file, version:version, path:path, kb:kb, bulletin:bulletin, product:prod) == HCF_OLDER )
      vuln = TRUE;

    path = hotfix_get_officecommonfilesdir(officever:'15.0');
    path = hotfix_append_path(path:path, value:'Microsoft Shared\\Office15');
    kb = '5002119';
    file = 'mso.dll';
    version = '15.0.5415.1000';
    if (hotfix_check_fversion(file:file, version:version, path:path, kb:kb, bulletin:bulletin, product:prod) == HCF_OLDER )
      vuln = TRUE;

    path = hotfix_get_officeprogramfilesdir(officever:'15.0');
    path = hotfix_append_path(path:path, value:'Microsoft Office\\Office15');
    kb = '5002064';
    file = 'graph.exe';
    version = '15.0.5415.1000';
    if (hotfix_check_fversion(file:file, version:version, path:path, kb:kb, bulletin:bulletin, product:prod) == HCF_OLDER )
      vuln = TRUE;

    path = hotfix_get_officeprogramfilesdir(officever:'15.0');
    path = hotfix_append_path(path:path, value:'Microsoft Office\\Office15');
    kb = '4462205';
    file = 'stslist.dll';
    version = '15.0.5415.1000';
    if (hotfix_check_fversion(file:file, version:version, path:path, kb:kb, bulletin:bulletin, product:prod) == HCF_OLDER )
      vuln = TRUE;
  }
}

# Office 2016
if (office_vers['16.0'])
{
  office_sp = get_kb_item('SMB/Office/2016/SP');
  if (!isnull(office_sp) && office_sp == 0)
  {
    prod = 'Microsoft Office 2016';
    
    # MSI mso.dll
    path = hotfix_get_officecommonfilesdir(officever:'16.0');
    path = hotfix_append_path(path:path, value:'Microsoft Shared\\Office16');
    if (hotfix_check_fversion(file:'mso.dll', version:'16.0.5266.1000', channel:'MSI', channel_product:'Office', path:path, kb:'5002116', bulletin:bulletin, product:prod) == HCF_OLDER)
      vuln = TRUE;

    # MSI graph.exe
    path = hotfix_get_officeprogramfilesdir(officever:'16.0');
    path = hotfix_append_path(path:path, value:'Microsoft Office\\Office16');
    if (hotfix_check_fversion(file:'graph.exe', version:'16.0.5266.1000', channel:'MSI', channel_product:'Office', path:path, kb:'5002060', bulletin:bulletin, product:prod) == HCF_OLDER)
      vuln = TRUE;

    # MSI stslist.dll
    path = hotfix_get_officeprogramfilesdir(officever:'16.0');
    path = hotfix_append_path(path:path, value:'Microsoft Office\\Office16');
    if (hotfix_check_fversion(file:'stslist.dll', version:'16.0.5266.1000', channel:'MSI', channel_product:'Office', path:path, kb:'5002052', bulletin:bulletin, product:prod) == HCF_OLDER)
      vuln = TRUE;
    
    # MSI acecore.dll
    path = hotfix_get_officecommonfilesdir(officever:'16.0');
    path = hotfix_append_path(path:path, value:'Microsoft Shared\\Office16');
    if (hotfix_check_fversion(file:'acecore.dll', version:'16.0.5266.1001', channel:'MSI', channel_product:'Office', path:path, kb:'5002115', bulletin:bulletin, product:prod) == HCF_OLDER)
      vuln = TRUE;
  }
}

if (vuln)
{
  replace_kb_item(name:'SMB/Missing/'+bulletin, value:TRUE);
  hotfix_security_hole();
  hotfix_check_fversion_end();
  exit(0);
}
else
{
  hotfix_check_fversion_end();
  audit(AUDIT_HOST_NOT, 'affected');
}
