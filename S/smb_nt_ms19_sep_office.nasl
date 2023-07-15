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
  script_id(128648);
  script_version("1.12");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/25");

  script_cve_id(
    "CVE-2019-1246",
    "CVE-2019-1263",
    "CVE-2019-1264",
    "CVE-2019-1297"
  );
  script_xref(name:"MSKB", value:"4464566");
  script_xref(name:"MSKB", value:"4475607");
  script_xref(name:"MSKB", value:"4475599");
  script_xref(name:"MSKB", value:"4475611");
  script_xref(name:"MSKB", value:"4475583");
  script_xref(name:"MSKB", value:"4475591");
  script_xref(name:"MSFT", value:"MS19-4464566");
  script_xref(name:"MSFT", value:"MS19-4475607");
  script_xref(name:"MSFT", value:"MS19-4475599");
  script_xref(name:"MSFT", value:"MS19-4475611");
  script_xref(name:"MSFT", value:"MS19-4475583");
  script_xref(name:"MSFT", value:"MS19-4475591");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/03/17");

  script_name(english:"Security Updates for Microsoft Office Products (September 2019)");

  script_set_attribute(attribute:"synopsis", value:
"The Microsoft Office Products are affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The Microsoft Office Products are missing security updates.
It is, therefore, affected by multiple vulnerabilities :

  - A remote code execution vulnerability exists when the
    Windows Jet Database Engine improperly handles objects
    in memory. An attacker who successfully exploited this
    vulnerability could execute arbitrary code on a victim
    system. An attacker could exploit this vulnerability by
    enticing a victim to open a specially crafted file. The
    update addresses the vulnerability by correcting the way
    the Windows Jet Database Engine handles objects in
    memory. (CVE-2019-1246)

  - A remote code execution vulnerability exists in
    Microsoft Excel software when the software fails to
    properly handle objects in memory. An attacker who
    successfully exploited the vulnerability could run
    arbitrary code in the context of the current user. If
    the current user is logged on with administrative user
    rights, an attacker could take control of the affected
    system. An attacker could then install programs; view,
    change, or delete data; or create new accounts with full
    user rights.  (CVE-2019-1297)

  - An information disclosure vulnerability exists when
    Microsoft Excel improperly discloses the contents of its
    memory. An attacker who exploited the vulnerability
    could use the information to compromise the users
    computer or data.  (CVE-2019-1263)

  - A security feature bypass vulnerability exists when
    Microsoft Office improperly handles input. An attacker
    who successfully exploited the vulnerability could
    execute arbitrary commands. In a file-sharing attack
    scenario, an attacker could provide a specially crafted
    document file designed to exploit the vulnerability, and
    then convince a user to open the document file and
    interact with the document by clicking a specific cell.
    The update addresses the vulnerability by correcting how
    Microsoft Office handles input. (CVE-2019-1264)");
  # https://support.microsoft.com/en-us/help/4464566/security-update-for-office-2010-september-10-2019
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e3c39b6e");
  # https://support.microsoft.com/en-us/help/4475607/security-update-for-office-2013-september-10-2019
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?8c55c5d1");
  # https://support.microsoft.com/en-us/help/4475599/security-update-for-office-2010-september-10-2019
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?af806b4b");
  # https://support.microsoft.com/en-us/help/4475611/security-update-for-office-2013-september-10-2019
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0e38e73e");
  # https://support.microsoft.com/en-us/help/4475583/security-update-for-office-2016-september-10-2019
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?455b89a9");
  # https://support.microsoft.com/en-us/help/4475591/security-update-for-office-2016-september-10-2019
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f4aeff4f");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released the following security updates to address this issue:
  -KB4464566
  -KB4475607
  -KB4475599
  -KB4475611
  -KB4475583
  -KB4475591
For Office 365, Office 2016 C2R, or Office 2019, ensure
automatic updates are enabled or open any office app and
manually perform an update.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-1297");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/09/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/09/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/09/10");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:office");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2019-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("office_installed.nasl", "smb_hotfixes.nasl", "ms_bulletin_checks_possible.nasl");
  script_require_keys("SMB/MS_Bulletin_Checks/Possible");
  script_require_ports(139, 445, "Host/patch_management_checks");

  exit(0);
}

include('audit.inc');
include('smb_func.inc');
include('smb_hotfixes.inc');
include('smb_hotfixes_fcheck.inc');
include('smb_reg_query.inc');
include('misc_func.inc');
include('install_func.inc');

get_kb_item_or_exit('SMB/MS_Bulletin_Checks/Possible');

bulletin = 'MS19-09';
kbs = make_list(
  '4464566',
  '4475599',
  '4475607',
  '4475611',
  '4475583',
  '4475591'
);

if (get_kb_item("Host/patch_management_checks"))
  hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

get_kb_item_or_exit("SMB/Registry/Enumerated", exit_code:1);

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

    path = hotfix_get_officecommonfilesdir(officever:'14.0');
    path = hotfix_append_path(path:path, value:'Microsoft Shared\\Office14');
    kb = "4464566";
    file = "mso.dll";
    version = "14.0.7237.5000";
    if (hotfix_check_fversion(file:file, version:version, path:path, kb:kb, bulletin:bulletin, product:prod) == HCF_OLDER)
      vuln = TRUE;

    path = hotfix_get_officecommonfilesdir(officever:'14.0');
    path = hotfix_append_path(path:path, value:'Microsoft Shared\\Office14');
    kb = "4475599";
    file = "acecore.dll";
    version = "14.0.7237.5000";
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
    kb = '4475611';
    file = "acecore.dll";
    version = "15.0.5172.1000";
    if (hotfix_check_fversion(file:file, version:version, path:path, kb:kb, bulletin:bulletin, product:prod) == HCF_OLDER )
      vuln = TRUE;

    path = hotfix_get_officecommonfilesdir(officever:'15.0');
    path = hotfix_append_path(path:path, value:'Microsoft Shared\\Office15');
    kb = '4475607';
    file = "mso.dll";
    version = "15.0.5172.1000";
    if (hotfix_check_fversion(file:file, version:version, path:path, kb:kb, bulletin:bulletin, product:prod) == HCF_OLDER )
      vuln = TRUE;
  }
}

# Office 2016
if (office_vers["16.0"])
{
  office_sp = get_kb_item("SMB/Office/2016/SP");
  if (!isnull(office_sp) && office_sp == 0)
  {
    prod = "Microsoft Office 2016";
    prod2019 = "Microsoft Office 2019";

    path = hotfix_get_officecommonfilesdir(officever:"16.0");
    acecore_path = hotfix_append_path(path:path, value:"Microsoft Shared\Office16");
    # MSI aceexcl.dll
    if (hotfix_check_fversion(file:"acecore.dll", version:"16.0.4900.1000", channel:"MSI", channel_product:"Office", path:acecore_path, kb:'4475591', bulletin:bulletin, product:prod) == HCF_OLDER)
      vuln = TRUE;

    path = hotfix_get_officecommonfilesdir(officever:"16.0");
    mso_dll_path = hotfix_append_path(path:path, value:"Microsoft Shared\Office16");
    if (hotfix_check_fversion(file:"mso.dll", version:"16.0.4900.1000", channel:"MSI", channel_product:"Office", path:mso_dll_path, kb:'4475583', bulletin:bulletin, product:prod) == HCF_OLDER)
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
