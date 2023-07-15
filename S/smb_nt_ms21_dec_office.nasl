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
  script_id(156062);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/16");

  script_cve_id(
    "CVE-2021-42293",
    "CVE-2021-42295",
    "CVE-2021-43255",
    "CVE-2021-43256",
    "CVE-2021-43875"
  );
  script_xref(name:"MSKB", value:"4486726");
  script_xref(name:"MSKB", value:"4504710");
  script_xref(name:"MSKB", value:"4504745");
  script_xref(name:"MSKB", value:"5002033");
  script_xref(name:"MSKB", value:"5002099");
  script_xref(name:"MSKB", value:"5002101");
  script_xref(name:"MSKB", value:"5002104");
  script_xref(name:"MSFT", value:"MS21-4504710");
  script_xref(name:"MSFT", value:"MS21-4504745");
  script_xref(name:"MSFT", value:"MS21-4486726");
  script_xref(name:"MSFT", value:"MS21-5002033");
  script_xref(name:"MSFT", value:"MS21-5002099");
  script_xref(name:"MSFT", value:"MS21-5002101");
  script_xref(name:"MSFT", value:"MS21-5002104");
  script_xref(name:"IAVA", value:"2021-A-0584-S");

  script_name(english:"Security Updates for Microsoft Office Products (December 2021)");

  script_set_attribute(attribute:"synopsis", value:
"The Microsoft Office Products are affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The Microsoft Office Products are missing security updates. It is, therefore, affected by multiple vulnerabilities:

  - A remote code execution vulnerability. An attacker can exploit this to bypass authentication and execute
    unauthorized arbitrary commands. (CVE-2021-43256, CVE-2021-43875)

  - An elevation of privilege vulnerability. An attacker can exploit this to gain elevated privileges.
    (CVE-2021-42293)

  - A session spoofing vulnerability exists. An attacker can exploit this to perform actions with the
    privileges of another user. (CVE-2021-43255)

  - An information disclosure vulnerability. An attacker can exploit this to disclose potentially sensitive
    information. (CVE-2021-42295)");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/4504710");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/4504745");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/4486726");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5002033");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5002099");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5002101");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5002104");
  # https://docs.microsoft.com/en-us/officeupdates/update-history-office-2019
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?42ab6861");
  # https://docs.microsoft.com/en-us/officeupdates/update-history-microsoft365-apps-by-date
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?fd4508ff");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released the following security updates to address this issue:
  -KB4504710
  -KB4504745
  -KB4486726
  -KB5002033
  -KB5002099
  -KB5002104
  -KB5002101

For Office 365, Office 2016 C2R, or Office 2019, ensure automatic
updates are enabled or open any office app and manually perform an
update.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-43875");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/12/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/12/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/12/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:office");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2021-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

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

var bulletin = 'MS21-12';
var kbs = make_list(
  '4504710',
  '4504745',
  '4486726',
  '5002033',
  '5002099',
  '5002104',
  '5002101'
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
    kb = '5002104';
    file = 'acecore.dll';
    version = '15.0.5405.1000';
    if (hotfix_check_fversion(file:file, version:version, path:path, kb:kb, bulletin:bulletin, product:prod) == HCF_OLDER )
      vuln = TRUE;

    path = hotfix_get_officecommonfilesdir(officever:'15.0');
    path = hotfix_append_path(path:path, value:'Microsoft Shared\\Office15');
    kb = '5002101';
    file = 'mso.dll';
    version = '15.0.5407.1000';
    if (hotfix_check_fversion(file:file, version:version, path:path, kb:kb, bulletin:bulletin, product:prod) == HCF_OLDER )
      vuln = TRUE;

    path = hotfix_get_officecommonfilesdir(officever:'15.0');
    path = hotfix_append_path(path:path, value:'Microsoft Shared\\VBA\\VBA7.1');
    kb = '4486726';
    file = 'vbe7.dll';
    version = '7.1.11.16';
    if (hotfix_check_fversion(file:file, version:version, path:path, kb:kb, bulletin:bulletin, product:prod) == HCF_OLDER)
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

    path = hotfix_get_officecommonfilesdir(officever:'16.0');
    path = hotfix_append_path(path:path, value:'Microsoft Shared\\VBA\\VBA7.1');
    kb = '4504710';
    file = 'vbe7.dll';
    version = '7.1.11.16';
    # MSI vbe7.dll
    if (hotfix_check_fversion(file:file, version:version, channel:'MSI', channel_product:'Office', path:path, kb:kb, bulletin:bulletin, product:prod) == HCF_OLDER)
      vuln = TRUE;

    path = hotfix_get_officecommonfilesdir(officever:'16.0');
    path = hotfix_append_path(path:path, value:'Microsoft Shared\\Office16');
    kb = '5002033';
    file = 'mso.dll';
    version = '16.0.5254.1001';
    # MSI mso.dll
    if (hotfix_check_fversion(file:file, version:version, channel:'MSI', channel_product:'Office', path:path, kb:kb, bulletin:bulletin, product:prod) == HCF_OLDER)
      vuln = TRUE;

    path = hotfix_get_officecommonfilesdir(officever:'16.0');
    path = hotfix_append_path(path:path, value:'Microsoft Shared\\Office16');
    kb = '4504745';
    file = 'mso20win32client.dll';
    version = '16.0.5254.1001';
    # MSI mso.dll
    if (hotfix_check_fversion(file:file, version:version, channel:'MSI', channel_product:'Office', path:path, kb:kb, bulletin:bulletin, product:prod) == HCF_OLDER)
      vuln = TRUE;

    path = hotfix_get_officecommonfilesdir(officever:'16.0');
    path = hotfix_append_path(path:path, value:'Microsoft Shared\\Office16');
    kb = '5002099';
    file = 'acecore.dll';
    version = '16.0.5251.1000';
    # MSI acecore.dll
    if (hotfix_check_fversion(file:file, version:version, channel:'MSI', channel_product:'Office', path:path, kb:kb, bulletin:bulletin, product:prod) == HCF_OLDER)
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
