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
  script_id(144885);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/07");

  script_cve_id(
    "CVE-2021-1711",
    "CVE-2021-1714",
    "CVE-2021-1715",
    "CVE-2021-1716"
  );
  script_xref(name:"MSKB", value:"4493168");
  script_xref(name:"MSKB", value:"4486759");
  script_xref(name:"MSKB", value:"4493181");
  script_xref(name:"MSKB", value:"4486755");
  script_xref(name:"MSKB", value:"4486762");
  script_xref(name:"MSKB", value:"4493143");
  script_xref(name:"MSKB", value:"4493142");
  script_xref(name:"MSFT", value:"MS21-4493168");
  script_xref(name:"MSFT", value:"MS21-4486759");
  script_xref(name:"MSFT", value:"MS21-4493181");
  script_xref(name:"MSFT", value:"MS21-4486755");
  script_xref(name:"MSFT", value:"MS21-4486762");
  script_xref(name:"MSFT", value:"MS21-4493143");
  script_xref(name:"MSFT", value:"MS21-4493142");
  script_xref(name:"IAVA", value:"2021-A-0016-S");
  script_xref(name:"IAVA", value:"2021-A-0017-S");
  script_xref(name:"IAVA", value:"2021-A-0024-S");
  script_xref(name:"CEA-ID", value:"CEA-2021-0001");

  script_name(english:"Security Updates for Microsoft Office Products (January 2021)");

  script_set_attribute(attribute:"synopsis", value:
"The Microsoft Office Products are affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The Microsoft office Product is missing security updates. It is, therefore, affected by multiple vulnerabilities:

  - Microsoft Office Remote Code Execution Vulnerability (CVE-2021-1711)

  - Microsoft Excel Remote Code Execution Vulnerability (CVE-2021-1714)

  - Microsoft Word Remote Code Execution Vulnerability (CVE-2021-1715, CVE-2021-1716)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://support.microsoft.com/en-us/help/4486759/security-update-for-office-2013-january-12-2021
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c9a0f393");
  # https://support.microsoft.com/en-us/help/4493168/security-update-for-office-2016-january-12-2021
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?929293ed");
  # https://support.microsoft.com/en-us/help/4493181/security-update-for-office-2010-january-12-2021
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?45b1c4b0");
  # https://support.microsoft.com/en-us/help/4486755/security-update-for-office-2016-january-12-2021
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?4bc39b5e");
  # https://support.microsoft.com/en-us/help/4486762/security-update-for-office-2013-january-12-2021
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?45f77592");
  # https://support.microsoft.com/en-us/help/4493142/security-update-for-office-2010-january-12-2021
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?861b61c6");
  # https://support.microsoft.com/en-us/help/4493143/security-update-for-office-2010-january-12-2021
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?58c9afc9");
  # https://support.microsoft.com/en-us/help/4493142/security-update-for-office-2010-january-12-2021
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?861b61c6");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released the following security updates to address this issue:  
  -KB4486759
  -KB4493168
  -KB4493181
  -KB4486755
  -KB4486762
  -KB4493142
  -KB4493143

For Office 365, Office 2016 C2R, or Office 2019, ensure automatic
updates are enabled or open any office app and manually perform an
update.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-1716");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/01/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/01/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/01/12");

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

bulletin = 'MS21-01';
kbs = make_list(
  '4493168',
  '4486759',
  '4493181',
  '4486755',
  '4486762',
  '4493143',
  '4493142'
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
    kb = '4493181';
    file = 'graph.exe';
    version = '14.0.7264.5000';
    if (hotfix_check_fversion(file:file, version:version, path:path, kb:kb, bulletin:bulletin, product:prod) == HCF_OLDER)
      vuln = TRUE;

    path = hotfix_get_officecommonfilesdir(officever:'14.0');
    path = hotfix_append_path(path:path, value:'Microsoft Shared\\Office14');
    kb = '4493143';
    file = 'acecore.dll';
    version = '14.0.7264.5000';
    if (hotfix_check_fversion(file:file, version:version, path:path, kb:kb, bulletin:bulletin, product:prod) == HCF_OLDER)
      vuln = TRUE;

    # wwlibcxm.dll only exists if KB2428677 is installed
    path = hotfix_get_officeprogramfilesdir(officever:'14.0');
    path = hotfix_append_path(path:path, value:'Microsoft Office\\Office14');
    kb = '4493142';
    file = 'wwlibcxm.dll';
    version = '14.0.7264.5000';
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
    kb = '4486759';
    file = 'graph.exe';
    version = '15.0.5311.1000';
    if (hotfix_check_fversion(file:file, version:version, path:path, kb:kb, bulletin:bulletin, product:prod) == HCF_OLDER )
      vuln = TRUE;

    path = hotfix_get_officecommonfilesdir(officever:'15.0');
    path = hotfix_append_path(path:path, value:'Microsoft Shared\\Office15');
    kb = '4486762';
    file = 'acecore.dll';
    version = '15.0.5311.1000';
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
    if (hotfix_check_fversion(file:'graph.exe', version:'16.0.5110.1000', channel:'MSI', channel_product:'Office', path:path, kb:'4493168', bulletin:bulletin, product:prod) == HCF_OLDER)
      vuln = TRUE;
  
    path = hotfix_get_officecommonfilesdir(officever:'16.0');
    path = hotfix_append_path(path:path, value:'Microsoft Shared\\Office16');

    # MSI acecore.dll
    if (hotfix_check_fversion(file:'acecore.dll', version:'16.0.5110.1000', channel:'MSI', channel_product:'Office', path:path, kb:'4486755', bulletin:bulletin, product:prod) == HCF_OLDER)
      vuln = TRUE;

    prod2019 = 'Microsoft Office 2019';
    path = hotfix_get_officeprogramfilesdir(officever:'16.0');
    graph_exe_path = hotfix_append_path(path:path, value:'Microsoft Office\\root\\Office16');
    
    path = hotfix_get_officecommonfilesdir(officever:'16.0');
    mso_dll_path = hotfix_append_path(path:path, value:'Microsoft Shared\\Office16');
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
