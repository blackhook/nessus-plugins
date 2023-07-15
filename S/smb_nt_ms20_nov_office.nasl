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
  script_id(142689);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/05");

  script_cve_id("CVE-2020-17062", "CVE-2020-17064");
  script_xref(name:"MSKB", value:"4484534");
  script_xref(name:"MSKB", value:"4484520");
  script_xref(name:"MSKB", value:"4486722");
  script_xref(name:"MSKB", value:"4486737");
  script_xref(name:"MSKB", value:"4484455");
  script_xref(name:"MSKB", value:"4486738");
  script_xref(name:"MSKB", value:"4484508");
  script_xref(name:"MSKB", value:"4486725");
  script_xref(name:"MSFT", value:"MS20-4484534");
  script_xref(name:"MSFT", value:"MS20-4484520");
  script_xref(name:"MSFT", value:"MS20-4486722");
  script_xref(name:"MSFT", value:"MS20-4486737");
  script_xref(name:"MSFT", value:"MS20-4484455");
  script_xref(name:"MSFT", value:"MS20-4486738");
  script_xref(name:"MSFT", value:"MS20-4484508");
  script_xref(name:"MSFT", value:"MS20-4486725");
  script_xref(name:"IAVA", value:"2020-A-0516-S");
  script_xref(name:"CEA-ID", value:"CEA-2020-0135");

  script_name(english:"Security Updates for Microsoft Office Products (November 2020)");

  script_set_attribute(attribute:"synopsis", value:
"The Microsoft Office Products are affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The Microsoft office Product is missing security updates.

  - Microsoft Office Access Connectivity Engine Remote Code Execution Vulnerability (CVE-2020-17062)

  - Microsoft Excel Remote Code Execution Vulnerability This CVE ID is unique from CVE-2020-17019,
    CVE-2020-17065, CVE-2020-17066. (CVE-2020-17064)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://support.microsoft.com/en-us/help/4484534/security-update-for-office-2010-november-10-2020
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?312a864d");
  # https://support.microsoft.com/en-us/help/4484520/security-update-for-office-2013-november-10-2020
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f48f7593");
  # https://support.microsoft.com/en-us/help/4486722/security-update-for-office-2016-november-10-2020
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?33234980");
  # https://support.microsoft.com/en-us/help/4486737/security-update-for-office-2010-november-10-2020
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?bb281f52");
  # https://support.microsoft.com/en-us/help/4484455/security-update-for-office-2010-november-10-2020
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?80901ffe");
  # https://support.microsoft.com/en-us/help/4486738/security-update-for-office-2010-november-10-2020
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c9c18f6d");
  # https://support.microsoft.com/en-us/help/4484508/security-update-for-office-2016-november-10-2020
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?6846380b");
  # https://support.microsoft.com/en-us/help/4486725/security-update-for-office-2013-november-10-2020
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b0c497b5");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released the following security updates to address this issue:  
  -KB4484534
  -KB4484520
  -KB4486722
  -KB4486737
  -KB4484455
  -KB4486738
  -KB4484508
  -KB4486725

For Office 365, Office 2016 C2R, or Office 2019, ensure automatic updates are enabled or open any office app and
manually perform an update.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-17019");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/11/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/11/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/11/10");

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

bulletin = 'MS20-11';
kbs = make_list(
  '4484534',
  '4484520',
  '4486722',
  '4486737',
  '4486725',
  '4484508'
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
    kb = '4486738';
    file = 'wwlibcxm.dll';
    version = '14.0.7262.5000';
    if (hotfix_check_fversion(file:file, version:version, path:path, kb:kb, bulletin:bulletin, product:prod) == HCF_OLDER)
      vuln = TRUE;

    path = hotfix_get_officecommonfilesdir(officever:'14.0');
    path = hotfix_append_path(path:path, value:'Microsoft Shared\\Office14');
    kb = '4484534';
    file = 'acecore.dll';
    version = '14.0.7262.5000';
    if (hotfix_check_fversion(file:file, version:version, path:path, kb:kb, bulletin:bulletin, product:prod) == HCF_OLDER)
      vuln = TRUE;

    path = hotfix_get_officeprogramfilesdir(officever:'14.0');
    path = hotfix_append_path(path:path, value:'Microsoft Office\\Office14');
    kb = '4486737';
    file = 'graph.exe';
    version = '14.0.7262.5000';
    if (hotfix_check_fversion(file:file, version:version, path:path, kb:kb, bulletin:bulletin, product:prod) == HCF_OLDER)
      vuln = TRUE;

    path = hotfix_get_officecommonfilesdir(officever:'14.0');
    path = hotfix_append_path(path:path, value:'Microsoft Shared\\VBA\\VBA7');
    kb = '4484455';
    file = 'vbe7.dll';
    version = '7.0.16.47';
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

    path = hotfix_get_officecommonfilesdir(officever:'15.0');
    path = hotfix_append_path(path:path, value:'Microsoft Shared\\Office15');
    kb = '4484520';
    file = 'acecore.dll';
    version = '15.0.5293.1000';
    if (hotfix_check_fversion(file:file, version:version, path:path, kb:kb, bulletin:bulletin, product:prod) == HCF_OLDER)
      vuln = TRUE;

    path = hotfix_get_officeprogramfilesdir(officever:'15.0');
    path = hotfix_append_path(path:path, value:'Microsoft Office\\Office15');
    kb = '4486725';
    file = 'graph.exe';
    version = '15.0.5293.1000';
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
    
    path = hotfix_get_officeprogramfilesdir(officever:'16.0');
    path = hotfix_append_path(path:path, value:'Microsoft Office\\Office16');

    # MSI graph.exe
    if (hotfix_check_fversion(file:'graph.exe', version:'16.0.5083.1000', channel:'MSI', channel_product:'Office', path:path, kb:'4486722', bulletin:bulletin, product:prod) == HCF_OLDER)
      vuln = TRUE;
    
    path = hotfix_get_officecommonfilesdir(officever:'16.0');
    path = hotfix_append_path(path:path, value:'Microsoft Shared\\Office16');

    # MSI acecore.dll
    if (hotfix_check_fversion(file:'acecore.dll', version:'16.0.5083.1000', channel:'MSI', channel_product:'Office', path:path, kb:'4484508', bulletin:bulletin, product:prod) == HCF_OLDER)
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
