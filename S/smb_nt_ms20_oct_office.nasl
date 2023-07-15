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
  script_id(141418);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/05");

  script_cve_id(
    "CVE-2020-16929",
    "CVE-2020-16930",
    "CVE-2020-16954",
    "CVE-2020-16957"
  );
  script_xref(name:"MSKB", value:"4484417");
  script_xref(name:"MSKB", value:"4484435");
  script_xref(name:"MSKB", value:"4486682");
  script_xref(name:"MSKB", value:"4486688");
  script_xref(name:"MSKB", value:"4486700");
  script_xref(name:"MSFT", value:"MS20-4484417");
  script_xref(name:"MSFT", value:"MS20-4484435");
  script_xref(name:"MSFT", value:"MS20-4486682");
  script_xref(name:"MSFT", value:"MS20-4486688");
  script_xref(name:"MSFT", value:"MS20-4486700");
  script_xref(name:"IAVA", value:"2020-A-0454-S");
  script_xref(name:"IAVA", value:"2020-A-0462-S");
  script_xref(name:"CEA-ID", value:"CEA-2020-0126");

  script_name(english:"Security Updates for Microsoft Office Products (October 2020)");

  script_set_attribute(attribute:"synopsis", value:
"The Microsoft Office Products are affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The Microsoft Office Products are missing security updates. It is, therefore, affected by multiple vulnerabilities :

  - A remote code execution vulnerability exists in Microsoft Excel software when the software fails to
    properly handle objects in memory. An attacker who successfully exploited the vulnerability could run
    arbitrary code in the context of the current user. If the current user is logged on with administrative
    user rights, an attacker could take control of the affected system. An attacker could then install
    programs; view, change, or delete data; or create new accounts with full user rights. (CVE-2020-16929,
    CVE-2020-16930)

  - A remote code execution vulnerability exists in Microsoft Office software when the software fails to
    properly handle objects in memory. An attacker who successfully exploited the vulnerability could run
    arbitrary code in the context of the current user. If the current user is logged on with administrative
    user rights, an attacker could take control of the affected system. An attacker could then install
    programs; view, change, or delete data; or create new accounts with full user rights. (CVE-2020-16954)

  - A remote code execution vulnerability exists when the Microsoft Office Access Connectivity Engine improperly
    handles objects in memory. An attacker who successfully exploited this vulnerability could execute arbitrary 
    code on a victim system.(CVE-2020-16957)");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/4484417");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/4484435");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/4486682");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/4486688");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/4486700");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released the following security updates to address this issue:  
  -KB4484417
  -KB4484435
  -KB4486682
  -KB4486688
  -KB4486700

For Office 365, Office 2016 C2R, or Office 2019, ensure automatic updates are enabled or open any office app and
manually perform an update.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-16957");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/10/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/10/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/10/13");

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

bulletin = 'MS20-10';
kbs = make_list(
  '4484417',
  '4484435',
  '4486682',
  '4486688',
  '4486700'
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

    path = hotfix_get_officeprogramfilesdir(officever:'14.0');
    path = hotfix_append_path(path:path, value:'Microsoft Office\\Office14');

    kb = '4486700';
    file = 'graph.exe';
    version = '14.0.7261.5000';
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
    path = hotfix_append_path(path:path, value:'Microsoft Shared\\VBA\\VBA7.1');
    kb = '4484435';
    file = 'vbe7.dll';
    version = '7.1.11.0';
    if (hotfix_check_fversion(file:file, version:version, path:path, kb:kb, bulletin:bulletin, product:prod) == HCF_OLDER )
      vuln = TRUE;

    path = hotfix_get_officeprogramfilesdir(officever:'15.0');
    path = hotfix_append_path(path:path, value:'Microsoft Office\\Office15');

    kb = '4486688';
    file = 'graph.exe';
    version = '15.0.5285.1000';
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

    path = hotfix_get_officecommonfilesdir(officever:'16.0');
    path = hotfix_append_path(path:path, value:'Microsoft Shared\\VBA\\VBA7.1');
    kb = '4484417';
    file = 'vbe7.dll';
    version = '7.1.11.0';
    # MSI vbe7.dll
    if (hotfix_check_fversion(file:file, version:version, channel:'MSI', channel_product:'Office', path:path, kb:kb, bulletin:bulletin, product:prod) == HCF_OLDER)
      vuln = TRUE;
    
    path = hotfix_get_officeprogramfilesdir(officever:'16.0');
    path = hotfix_append_path(path:path, value:'Microsoft Office\\Office16');

    # MSI graph.exe
    if (hotfix_check_fversion(file:'graph.exe', version:'16.0.5071.1000', channel:'MSI', channel_product:'Office', path:path, kb:'4486682', bulletin:bulletin, product:prod) == HCF_OLDER)
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
