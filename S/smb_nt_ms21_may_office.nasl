#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from the Microsoft Security Updates API. The text
# itself is copyright (C) Microsoft Corporation.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(149401);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/06/10");

  script_cve_id(
    "CVE-2021-28455",
    "CVE-2021-31174",
    "CVE-2021-31175",
    "CVE-2021-31176",
    "CVE-2021-31178",
    "CVE-2021-31179",
    "CVE-2021-31180"
  );
  script_xref(name:"MSKB", value:"4464542");
  script_xref(name:"MSKB", value:"4493197");
  script_xref(name:"MSKB", value:"4493206");
  script_xref(name:"MSKB", value:"5001920");
  script_xref(name:"MSKB", value:"5001923");
  script_xref(name:"MSKB", value:"5001925");
  script_xref(name:"MSKB", value:"5001927");
  script_xref(name:"MSFT", value:"MS21-4464542");
  script_xref(name:"MSFT", value:"MS21-4493206");
  script_xref(name:"MSFT", value:"MS21-4493197");
  script_xref(name:"MSFT", value:"MS21-5001920");
  script_xref(name:"MSFT", value:"MS21-5001923");
  script_xref(name:"MSFT", value:"MS21-5001925");
  script_xref(name:"MSFT", value:"MS21-5001927");
  script_xref(name:"IAVA", value:"2021-A-0225-S");

  script_name(english:"Security Updates for Microsoft Office Products (May 2021)");

  script_set_attribute(attribute:"synopsis", value:
"The Microsoft Office Products are affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The Microsoft Office Products are missing security updates. It is, therefore, affected by multiple vulnerabilities:

  - A remote code execution vulnerability. An attacker can exploit this to bypass authentication and execute
    unauthorized arbitrary commands. (CVE-2021-28455, CVE-2021-31175, CVE-2021-31176, CVE-2021-31177,
    CVE-2021-31179, CVE-2021-31180)

  - An information disclosure vulnerability. An attacker can exploit this to disclose potentially sensitive
    information. (CVE-2021-31174, CVE-2021-31178)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/4464542");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/4493197");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/4493206");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5001920");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5001923");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5001925");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5001927");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released the following security updates to address these issues:  
  -KB4464542
  -KB4493206
  -KB4493197
  -KB5001920
  -KB5001923
  -KB5001925
  -KB5001927
  
For Office 365, Office 2016 C2R, or Office 2019, ensure automatic updates are enabled or open any office app and
manually perform an update.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-31180");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2021-28455");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/05/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/05/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/05/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:office");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2021-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

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

var bulletin = 'MS21-05';
var kbs = make_list(
  '4464542',
  '4493197',
  '4493206',
  '5001920',
  '5001923',
  '5001925',
  '5001927'
);

if (get_kb_item('Host/patch_management_checks'))
  hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_WARNING);

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
    kb = '5001925';
    file = 'mso.dll';
    version = '15.0.5345.1002';
    if (hotfix_check_fversion(file:file, version:version, path:path, kb:kb, bulletin:bulletin, product:prod) == HCF_OLDER )
      vuln = TRUE;

    path = hotfix_get_officeprogramfilesdir(officever:'15.0');
    path = hotfix_append_path(path:path, value:'Microsoft Office\\Office15');
    kb = '5001927';
    file = 'graph.exe';
    version = '15.0.5345.1000';
    if (hotfix_check_fversion(file:file, version:version, path:path, kb:kb, bulletin:bulletin, product:prod) == HCF_OLDER )
      vuln = TRUE;

    path = hotfix_get_officecommonfilesdir(officever:'15.0');
    path = hotfix_append_path(path:path, value:'Microsoft Shared\\Office15');
    kb = '4493206';
    file = 'acecore.dll';
    version = '15.0.5345.1001';
    if (hotfix_check_fversion(file:file, version:version, path:path, kb:kb, bulletin:bulletin, product:prod) == HCF_OLDER )
      vuln = TRUE;

    path = hotfix_get_officeprogramfilesdir(officever:'15.0');
    path = hotfix_append_path(path:path, value:'Microsoft Office\\Office15');
    kb = '4464542';
    file = 'oart.dll';
    version = '15.0.5345.1000';
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
    
    # MSI graph.exe
    path = hotfix_get_officeprogramfilesdir(officever:'16.0');
    path = hotfix_append_path(path:path, value:'Microsoft Office\\Office16');
    if (hotfix_check_fversion(file:'graph.exe', version:'16.0.5161.1000', channel:'MSI', channel_product:'Office', path:path, kb:'5001923', bulletin:bulletin, product:prod) == HCF_OLDER)
      vuln = TRUE;
    
    # MSI mso.dll
    path = hotfix_get_officecommonfilesdir(officever:'16.0');
    path = hotfix_append_path(path:path, value:'Microsoft Shared\\Office16');
    if (hotfix_check_fversion(file:'mso.dll', version:'16.0.5161.1002', channel:'MSI', channel_product:'Office', path:path, kb:'5001920', bulletin:bulletin, product:prod) == HCF_OLDER)
      vuln = TRUE;
    
    # MSI acecore.dll
    path = hotfix_get_officecommonfilesdir(officever:'16.0');
    path = hotfix_append_path(path:path, value:'Microsoft Shared\\Office16');
    if (hotfix_check_fversion(file:'acecore.dll', version:'16.0.5161.1001', channel:'MSI', channel_product:'Office', path:path, kb:'4493197', bulletin:bulletin, product:prod) == HCF_OLDER)
      vuln = TRUE;
  }
}

if (vuln)
{
  replace_kb_item(name:'SMB/Missing/'+bulletin, value:TRUE);
  hotfix_security_warning();
  hotfix_check_fversion_end();
  exit(0);
}
else
{
  hotfix_check_fversion_end();
  audit(AUDIT_HOST_NOT, 'affected');
}
