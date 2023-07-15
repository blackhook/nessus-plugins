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
  script_id(153387);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/25");

  script_cve_id(
    "CVE-2021-38646",
    "CVE-2021-38650",
    "CVE-2021-38655",
    "CVE-2021-38657",
    "CVE-2021-38658",
    "CVE-2021-38659",
    "CVE-2021-38660"
  );
  script_xref(name:"MSKB", value:"4484103");
  script_xref(name:"MSKB", value:"4484108");
  script_xref(name:"MSKB", value:"5001958");
  script_xref(name:"MSKB", value:"5001997");
  script_xref(name:"MSKB", value:"5002005");
  script_xref(name:"MSKB", value:"5002007");
  script_xref(name:"MSFT", value:"MS21-4484103");
  script_xref(name:"MSFT", value:"MS21-4484108");
  script_xref(name:"MSFT", value:"MS21-5001958");
  script_xref(name:"MSFT", value:"MS21-5001997");
  script_xref(name:"MSFT", value:"MS21-5002005");
  script_xref(name:"MSFT", value:"MS21-5002007");
  script_xref(name:"IAVA", value:"2021-A-0428-S");
  script_xref(name:"IAVA", value:"2021-A-0425-S");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/04/18");

  script_name(english:"Security Updates for Microsoft Office Products (September 2021)");

  script_set_attribute(attribute:"synopsis", value:
"The Microsoft Office Products are affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The Microsoft Office Products are missing security updates. It is, therefore, affected by multiple vulnerabilities:

  - A session spoofing vulnerability exists. An attacker can exploit this to perform actions with the
    privileges of another user. (CVE-2021-38650)

  - A remote code execution vulnerability. An attacker can exploit this to bypass authentication and execute
    unauthorized arbitrary commands. (CVE-2021-38646, CVE-2021-38655, CVE-2021-38658, CVE-2021-38659,
      CVE-2021-38660)

  - An information disclosure vulnerability in the graphics component. An attacker can exploit this to
    disclose sensitive information. (CVE-2021-38657)");
  # https://support.microsoft.com/en-us/topic/description-of-the-security-update-for-office-2013-september-14-2021-kb5001958-8e7f4884-60d9-4af7-b1aa-3711ba83e697
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?7e88251c");
  # https://support.microsoft.com/en-us/topic/description-of-the-security-update-for-office-2016-september-14-2021-kb4484103-de2570a1-0fb2-a619-4930-f8836f4ebca2
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?9165ee58");
  # https://support.microsoft.com/en-us/topic/description-of-the-security-update-for-office-2016-september-14-2021-kb5002005-f9134f02-9c98-41c3-ae31-eaf3f89bc02a
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?bb69974a");
  # https://support.microsoft.com/en-us/topic/description-of-the-security-update-for-office-2013-september-14-2021-kb5002007-d50c1e46-7854-48ab-8695-4cb244c23a0d
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?babcfa70");
  # https://support.microsoft.com/en-us/topic/description-of-the-security-update-for-office-2016-september-14-2021-kb5001997-7ee3aeb4-230a-4002-9b50-2099a690e66c
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?3116725f");
  # https://support.microsoft.com/en-us/topic/description-of-the-security-update-for-office-2013-september-14-2021-kb4484108-c0eccc0b-46e5-6a39-ef33-2b88657e1bf5
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?2e7bac28");
  # https://docs.microsoft.com/en-us/officeupdates/update-history-office-2019
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?42ab6861");
  # https://docs.microsoft.com/en-us/officeupdates/update-history-microsoft365-apps-by-date
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?fd4508ff");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released the following security updates to address this issue:  
  -KB4484103
  -KB4484108
  -KB5001958
  -KB5001997
  -KB5002005
  -KB5002007

For Office 365, Office 2016 C2R, or Office 2019, ensure automatic
updates are enabled or open any office app and manually perform an
update.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-38660");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/09/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/09/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/09/14");

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

var bulletin = 'MS21-09';
var kbs = make_list(
  '5001958',
  '5001997',
  '5002007',
  '5002005',
  '4484108',
  '4484103'
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
    kb = '5001958';
    file = 'acecore.dll';
    version = '15.0.5349.1000';
    if (hotfix_check_fversion(file:file, version:version, path:path, kb:kb, bulletin:bulletin, product:prod) == HCF_OLDER )
      vuln = TRUE;

    path = hotfix_get_officecommonfilesdir(officever:'15.0');
    path = hotfix_append_path(path:path, value:'Microsoft Shared\\Office15');
    kb = '5002007';
    file = 'mso.dll';
    version = '15.0.5381.1000';
    if (hotfix_check_fversion(file:file, version:version, path:path, kb:kb, bulletin:bulletin, product:prod) == HCF_OLDER )
      vuln = TRUE;
      
    path = hotfix_get_officeprogramfilesdir(officever:'15.0');
    path = hotfix_append_path(path:path, value:'Microsoft Office\\Office15');
    kb = '4484108';
    file = 'osfproxy.dll';
    version = '15.0.5381.1000';
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
    path = hotfix_append_path(path:path, value:'Microsoft Shared\\Office16');

    # MSI acecore.dll
    if (hotfix_check_fversion(file:'acecore.dll', version:'16.0.5164.1000', channel:'MSI', channel_product:'Office', path:path, kb:'5001997', bulletin:bulletin, product:prod) == HCF_OLDER)
      vuln = TRUE;
    
    path = hotfix_get_officecommonfilesdir(officever:'16.0');
    path = hotfix_append_path(path:path, value:'Microsoft Shared\\Office16');

    # MSI mso.dll
    if (hotfix_check_fversion(file:'mso.dll', version:'16.0.5215.1000', channel:'MSI', channel_product:'Office', path:path, kb:'5002005', bulletin:bulletin, product:prod) == HCF_OLDER)
      vuln = TRUE;
    
    path = hotfix_get_officeprogramfilesdir(officever:'16.0');
    path = hotfix_append_path(path:path, value:'Microsoft Office\\Office16');

    # MSI osfproxy.dll
    if (hotfix_check_fversion(file:'osfproxy.dll', version:'16.0.5215.1000', channel:'MSI', channel_product:'Office', path:path, kb:'4484103', bulletin:bulletin, product:prod) == HCF_OLDER)
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
