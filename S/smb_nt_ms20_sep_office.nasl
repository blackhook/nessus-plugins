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
  script_id(140430);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/06");

  script_cve_id(
    "CVE-2020-1193",
    "CVE-2020-1218",
    "CVE-2020-1224",
    "CVE-2020-1332",
    "CVE-2020-1335",
    "CVE-2020-1338",
    "CVE-2020-1594"
  );
  script_xref(name:"MSKB", value:"4484513");
  script_xref(name:"MSKB", value:"4484533");
  script_xref(name:"MSKB", value:"4484532");
  script_xref(name:"MSKB", value:"4484517");
  script_xref(name:"MSKB", value:"4484530");
  script_xref(name:"MSKB", value:"4484469");
  script_xref(name:"MSKB", value:"4484466");
  script_xref(name:"MSFT", value:"MS20-4484513");
  script_xref(name:"MSFT", value:"MS20-4484533");
  script_xref(name:"MSFT", value:"MS20-4484532");
  script_xref(name:"MSFT", value:"MS20-4484517");
  script_xref(name:"MSFT", value:"MS20-4484530");
  script_xref(name:"MSFT", value:"MS20-4484469");
  script_xref(name:"MSFT", value:"MS20-4484466");
  script_xref(name:"IAVA", value:"2020-A-0406-S");
  script_xref(name:"CEA-ID", value:"CEA-2020-0118");

  script_name(english:"Security Updates for Microsoft Office Products (September 2020)");

  script_set_attribute(attribute:"synopsis", value:
"The Microsoft Office Products are affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The Microsoft Office Products are missing security updates. It is, therefore, affected by multiple vulnerabilities :

  - An information disclosure vulnerability exists when Microsoft Excel improperly discloses the contents of
    its memory. An attacker who exploited the vulnerability could use the information to compromise the users
    computer or data. (CVE-2020-1224)

  - A remote code execution vulnerability exists in Microsoft Excel software when the software fails to
    properly handle objects in memory. An attacker who successfully exploited the vulnerability could run
    arbitrary code in the context of the current user. If the current user is logged on with administrative
    user rights, an attacker could take control of the affected system. An attacker could then install
    programs; view, change, or delete data; or create new accounts with full user rights. (CVE-2020-1193,
    CVE-2020-1332, CVE-2020-1335, CVE-2020-1594)

  - A remote code execution vulnerability exists in Microsoft Word software when it fails to properly handle
    objects in memory. An attacker who successfully exploited the vulnerability could use a specially crafted
    file to perform actions in the security context of the current user. For example, the file could then take
    actions on behalf of the logged-on user with the same permissions as the current user. (CVE-2020-1218,
    CVE-2020-1338)");
  # https://support.microsoft.com/en-us/help/4484513/security-update-for-office-2016-september-8-2020
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e7235e57");
  # https://support.microsoft.com/en-us/help/4484533/security-update-for-office-2010-september-8-2020
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a759b2dc");
  # https://support.microsoft.com/en-us/help/4484532/security-update-for-office-2010-september-8-2020
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?14605c35");
  # https://support.microsoft.com/en-us/help/4484517/security-update-for-office-2013-september-8-2020
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?5437ab1c");
  # https://support.microsoft.com/en-us/help/4484530/security-update-for-office-2010-september-8-2020
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?393bb779");
  # https://support.microsoft.com/en-us/help/4484469/security-update-for-office-2013-september-8-2020
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?50416e37");
  # https://support.microsoft.com/en-us/help/4484466/security-update-for-office-2016-september-8-2020
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0271276c");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released the following security updates to address this issue:  
  -KB4484513
  -KB4484533
  -KB4484532
  -KB4484517
  -KB4484530
  -KB4484469
  -KB4484466

For Office 365, Office 2016 C2R, or Office 2019, ensure automatic updates are enabled or open any office app
and manually perform an update.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-1594");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/09/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/09/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/09/08");

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

bulletin = 'MS20-09';
kbs = make_list(
  '4484513',
  '4484532',
  '4484517',
  '4484530',
  '4484469',
  '4484466'
);

if (get_kb_item('Host/patch_management_checks'))
  hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_WARNING);

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
    kb = '4484533';
    file = 'wwlibcxm.dll';
    version = '14.0.7258.5000';
    if (hotfix_check_fversion(file:file, version:version, path:path, kb:kb, bulletin:bulletin, product:prod) == HCF_OLDER)
      vuln = TRUE;

    path = hotfix_get_officeprogramfilesdir(officever:'14.0');
    path = hotfix_append_path(path:path, value:'Microsoft Office\\Office14');
    kb = '4484532';
    file = 'graph.exe';
    version = '14.0.7258.5000';
    if (hotfix_check_fversion(file:file, version:version, path:path, kb:kb, bulletin:bulletin, product:prod) == HCF_OLDER)
      vuln = TRUE;

    path = hotfix_get_officecommonfilesdir(officever:'14.0');
    path = hotfix_append_path(path:path, value:'Microsoft Shared\\Office14');
    kb = '4484530';
    file = 'mso.dll';
    version = '14.0.7258.5000';
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
    kb = '4484517';
    file = 'graph.exe';
    version = '15.0.5275.1000';
    if (hotfix_check_fversion(file:file, version:version, path:path, kb:kb, bulletin:bulletin, product:prod) == HCF_OLDER )
      vuln = TRUE;

    path = hotfix_get_officecommonfilesdir(officever:'15.0');
    path = hotfix_append_path(path:path, value:'Microsoft Shared\\Office15');
    kb = '4484469';
    file = 'mso.dll';
    version = '15.0.5275.1000';
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
    
    path = hotfix_get_officeprogramfilesdir(officever:'16.0');
    path = hotfix_append_path(path:path, value:'Microsoft Office\\Office16');

    # MSI graph.exe
    if (hotfix_check_fversion(file:'graph.exe', version:'16.0.5056.1000', channel:'MSI', channel_product:'Office', path:path, kb:'4484513', bulletin:bulletin, product:prod) == HCF_OLDER)
      vuln = TRUE;
    
    path = hotfix_get_officecommonfilesdir(officever:'16.0');
    path = hotfix_append_path(path:path, value:'Microsoft Shared\\Office16');

    # MSI mso.dll
    if (hotfix_check_fversion(file:'mso.dll', version:'16.0.5056.1000', channel:'MSI', channel_product:'Office', path:path, kb:'4484466', bulletin:bulletin, product:prod) == HCF_OLDER)
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


