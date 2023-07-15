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
  script_id(132869);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/06/10");

  script_cve_id("CVE-2020-0652");
  script_xref(name:"MSKB", value:"4484221");
  script_xref(name:"MSKB", value:"4484227");
  script_xref(name:"MSKB", value:"4484236");
  script_xref(name:"MSFT", value:"MS20-4484221");
  script_xref(name:"MSFT", value:"MS20-4484227");
  script_xref(name:"MSFT", value:"MS20-4484236");
  script_xref(name:"IAVA", value:"2020-A-0029-S");

  script_name(english:"Security Updates for Microsoft Office Products (January 2020)");

  script_set_attribute(attribute:"synopsis", value:
"The Microsoft Office Products are affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The Microsoft Office Products are missing a security update. It is, therefore, affected by the following vulnerability:

  - A remote code execution vulnerability exists in Microsoft Office software when the software fails to
    properly handle objects in memory. An attacker who successfully exploited the vulnerability could run
    arbitrary code in the context of the current user. If the current user is logged on with administrative
    user rights, an attacker could take control of the affected system. An attacker could then install
    programs; view, change, or delete data; or create new accounts with full user rights.");
  # https://support.microsoft.com/en-us/help/4484236/security-update-for-office-2010-january-14-2020
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?1611bdcd");
  # https://support.microsoft.com/en-us/help/4484227/security-update-for-office-2013-january-14-2020
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d8161b35");
  # https://support.microsoft.com/en-us/help/4484221/security-update-for-office-2016-january-14-2020
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ff8ceaff");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released the following security updates to address this issue:  
  -KB4484221
  -KB4484227
  -KB4484236
  
For Office 365, Office 2016 C2R, or Office 2019, ensure automatic updates are enabled or open any office app and
manually perform an update.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-0652");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/01/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/01/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/01/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:office");
  script_set_attribute(attribute:"stig_severity", value:"II");
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

bulletin = 'MS20-01';
kbs = make_list(
  '4484236',  # Office 2010 SP2
  '4484227',  # Office 2013 SP1
  '4484221'   # Office 2016
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

    path = hotfix_get_officeprogramfilesdir(officever:'14.0');
    path = hotfix_append_path(path:path, value:'Microsoft Office\\Office14');
    kb = '4484236';
    file = 'graph.exe';
    version = '14.0.7244.5000';
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
    kb = '4484227';
    file = 'graph.exe';
    version = '15.0.5207.1000';
    if (hotfix_check_fversion(file:file, version:version, path:path, kb:kb, bulletin:bulletin, product:prod) == HCF_OLDER )
      vuln = TRUE;
  }
}

# Office 2016 / 2019 / C2R
if (office_vers['16.0'])
{
  office_sp = get_kb_item('SMB/Office/2016/SP');
  if (!isnull(office_sp) && office_sp == 0)
  {
    prod = 'Microsoft Office 2016';

    path = hotfix_get_officeprogramfilesdir(officever:'16.0');
    path = hotfix_append_path(path:path, value:'Microsoft Office\\Office16');

    # MSI graph.exe
    if (hotfix_check_fversion(file:'graph.exe', version:'16.0.4954.1000', channel:'MSI', channel_product:'Office', path:path, kb:'4484221', bulletin:bulletin, product:prod) == HCF_OLDER)
      vuln = TRUE;

    path = hotfix_get_officeprogramfilesdir(officever:'16.0');
    prod2019 = 'Microsoft Office 2019';
    mso_dll_path = hotfix_append_path(path:path, value:'Microsoft Office\\root\\Office16');
    c2r_path = mso_dll_path;
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
