#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from the Microsoft Security Updates API. The text
# itself is copyright (C) Microsoft Corporation.
#

include('compat.inc');

if (description)
{
  script_id(139499);
  script_version("1.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/05");

  script_cve_id(
    "CVE-2020-1494",
    "CVE-2020-1495",
    "CVE-2020-1496",
    "CVE-2020-1497",
    "CVE-2020-1503",
    "CVE-2020-1563",
    "CVE-2020-1581",
    "CVE-2020-1583"
  );
  script_xref(name:"MSKB", value:"4484346");
  script_xref(name:"MSKB", value:"4484354");
  script_xref(name:"MSKB", value:"4484359");
  script_xref(name:"MSKB", value:"4484375");
  script_xref(name:"MSKB", value:"4484379");
  script_xref(name:"MSKB", value:"4484431");
  script_xref(name:"MSKB", value:"4484492");
  script_xref(name:"MSFT", value:"MS20-4484346");
  script_xref(name:"MSFT", value:"MS20-4484354");
  script_xref(name:"MSFT", value:"MS20-4484359");
  script_xref(name:"MSFT", value:"MS20-4484375");
  script_xref(name:"MSFT", value:"MS20-4484379");
  script_xref(name:"MSFT", value:"MS20-4484431");
  script_xref(name:"MSFT", value:"MS20-4484492");
  script_xref(name:"IAVA", value:"2020-A-0359-S");
  script_xref(name:"IAVA", value:"2020-A-0365-S");
  script_xref(name:"IAVA", value:"2020-A-0369-S");
  script_xref(name:"CEA-ID", value:"CEA-2020-0101");

  script_name(english:"Security Updates for Microsoft Office Products (August 2020)");

  script_set_attribute(attribute:"synopsis", value:
"The Microsoft Office Products are affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The Microsoft Office Products are missing security updates. It is, therefore, affected by multiple vulnerabilities :

  - A remote code execution vulnerability exists in Microsoft Excel software when the software fails to
    properly handle objects in memory. An attacker who successfully exploited the vulnerability could run
    arbitrary code in the context of the current user. If the current user is logged on with administrative
    user rights, an attacker could take control of the affected system. An attacker could then install
    programs; view, change, or delete data; or create new accounts with full user rights. (CVE-2020-1494,
    CVE-2020-1495, CVE-2020-1496)

  - An information disclosure vulnerability exists when Microsoft Excel improperly discloses the contents of
    its memory. An attacker who exploited the vulnerability could use the information to compromise the users
    computer or data. (CVE-2020-1497)

  - An information disclosure vulnerability exists when Microsoft Word improperly discloses the contents of
    its memory. An attacker who exploited the vulnerability could use the information to compromise the users
    computer or data. (CVE-2020-1503, CVE-2020-1583)

  - A remote code execution vulnerability exists in Microsoft Office software when the software fails to
    properly handle objects in memory. An attacker who successfully exploited the vulnerability could run
    arbitrary code in the context of the current user. If the current user is logged on with administrative
    user rights, an attacker could take control of the affected system. An attacker could then install
    programs; view, change, or delete data; or create new accounts with full user rights. (CVE-2020-1563)

  - An elevation of privilege vulnerability exists in the way that Microsoft Office Click-to-Run (C2R)
    components handle objects in memory. An attacker who successfully exploited the vulnerability could
    elevate privileges. The attacker would need to already have the ability to execute code on the system.
    (CVE-2020-1581)");
  # https://support.microsoft.com/en-us/help/4484379/security-update-for-office-2010-august-11-2020
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c1185427");
  # https://support.microsoft.com/en-us/help/4484492/security-update-for-office-2010-august-11-2020
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?89246ae4");
  # https://support.microsoft.com/en-us/help/4484375/security-update-for-office-2010-august-11-2020
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?86785f90");
  # https://support.microsoft.com/en-us/help/4484354/security-update-for-office-2013-august-11-2020
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f3f269b7");
  # https://support.microsoft.com/en-us/help/4484359/security-update-for-office-2013-august-11-2020
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?00e42db9");
  # https://support.microsoft.com/en-us/help/4484431/security-update-for-office-2016-august-11-2020
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e456956b");
  # https://support.microsoft.com/en-us/help/4484346/security-update-for-office-2016-august-11-2020
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?5689b2e5");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released the following security updates to address this issue:  
  -KB4484346
  -KB4484354
  -KB4484359
  -KB4484375
  -KB4484379
  -KB4484431
  -KB4484492
  
For Office 365, Office 2016 C2R, or Office 2019, ensure automatic updates are enabled or open any office app and
manually perform an update.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-1581");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2020-1496");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/08/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/08/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/08/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:office");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2020-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("office_installed.nasl", "smb_hotfixes.nasl", "ms_bulletin_checks_possible.nasl");
  script_require_keys("SMB/MS_Bulletin_Checks/Possible");
  script_require_ports(139, 445, "Host/patch_management_checks");

  exit(0);
}

include('smb_func.inc');
include('smb_hotfixes.inc');
include('smb_hotfixes_fcheck.inc');
include('smb_reg_query.inc');
include('install_func.inc');

get_kb_item_or_exit('SMB/MS_Bulletin_Checks/Possible');

bulletin = 'MS20-08';
kbs = make_list(
  '4484346',
  '4484354',
  '4484359',
  '4484375',
  '4484379',
  '4484431',
  '4484492'
);

if (get_kb_item('Host/patch_management_checks'))
  hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

get_kb_item_or_exit('SMB/Registry/Enumerated', exit_code:1);

vuln = FALSE;
port = kb_smb_transport();

office_vers = hotfix_check_office_version();

# Office 2010 SP2
if (office_vers['14.0'])
{
  office_sp = get_kb_item('SMB/Office/2010/SP');
  if (!isnull(office_sp) && office_sp == 2)
  {
    prod = 'Microsoft Office 2010 SP2';

    # wwlibcxm.dll only exists if KB2428677 is installed
    path = hotfix_get_officeprogramfilesdir(officever:'14.0');
    path = hotfix_append_path(path:path, value:'Microsoft Office\\Office14');
    kb = '4484492';
    file = 'wwlibcxm.dll';
    version = '14.0.7256.5000';
    if (hotfix_check_fversion(file:file, version:version, path:path, kb:kb, bulletin:bulletin, product:prod) == HCF_OLDER)
      vuln = TRUE;

    path = hotfix_get_officeprogramfilesdir(officever:'14.0');
    path = hotfix_append_path(path:path, value:'Microsoft Office\\Office14');
    kb = '4484375';
    file = 'graph.exe';
    version = '14.0.7256.5000';
    if (hotfix_check_fversion(file:file, version:version, path:path, kb:kb, bulletin:bulletin, product:prod) == HCF_OLDER)
      vuln = TRUE;

    path = hotfix_get_officecommonfilesdir(officever:'14.0');
    path = hotfix_append_path(path:path, value:'Microsoft Shared\\OFFICE14');
    kb = '4484359';
    file = 'aceexcl.dll';
    version = '14.0.7256.5000';
    if (hotfix_check_fversion(file:file, version:version, path:path, kb:kb, bulletin:bulletin, product:prod) == HCF_OLDER)
      vuln = TRUE;
  }
}

# Office 2013 SP1
if (office_vers['15.0'])
{
  office_sp = get_kb_item('SMB/Office/2013/SP');
  if (!isnull(office_sp) && office_sp == 1)
  {
    prod = 'Microsoft Office 2013 SP1';

    path = hotfix_get_officeprogramfilesdir(officever:'15.0');
    path = hotfix_append_path(path:path, value:'Microsoft Office\\Office15');
    kb = '4484354';
    file = 'graph.exe';
    version = '15.0.5267.1000';
    if (hotfix_check_fversion(file:file, version:version, path:path, kb:kb, bulletin:bulletin, product:prod) == HCF_OLDER )
      vuln = TRUE;

    path = hotfix_get_officecommonfilesdir(officever:'15.0');
    path = hotfix_append_path(path:path, value:'Microsoft Shared\\OFFICE15');
    kb = '4484359';
    file = 'aceexcl.dll';
    version = '15.0.5267.1000';
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
    kb = '4484346';
    file = 'graph.exe';
    version = '16.0.5044.1000';
    if (hotfix_check_fversion(file:file, version:version, channel:'MSI', channel_product:'Office', path:path, kb:kb, bulletin:bulletin, product:prod) == HCF_OLDER)
      vuln = TRUE;
    
    # MSI aceexcl.dll
    path = hotfix_get_officecommonfilesdir(officever:'16.0');
    path = hotfix_append_path(path:path, value:'Microsoft Shared\\OFFICE16');
    kb = '4484431';
    file = 'aceexcl.dll';
    version = '16.0.5044.1000';
    if (hotfix_check_fversion(file:file, version:version, channel:'MSI', channel_product:'Office', path:path, kb:kb, bulletin:bulletin, product:prod) == HCF_OLDER)
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


