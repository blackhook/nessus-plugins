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
  script_id(154038);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/16");

  script_cve_id(
    "CVE-2021-40454",
    "CVE-2021-40471",
    "CVE-2021-40472",
    "CVE-2021-40473",
    "CVE-2021-40479"
  );
  script_xref(name:"MSKB", value:"4018332");
  script_xref(name:"MSKB", value:"4461476");
  script_xref(name:"MSKB", value:"5001982");
  script_xref(name:"MSKB", value:"5001985");
  script_xref(name:"MSFT", value:"MS21-4018332");
  script_xref(name:"MSFT", value:"MS21-4461476");
  script_xref(name:"MSFT", value:"MS21-5001982");
  script_xref(name:"MSFT", value:"MS21-5001985");
  script_xref(name:"IAVA", value:"2021-A-0472-S");
  script_xref(name:"IAVA", value:"2021-A-0475-S");
  script_xref(name:"IAVA", value:"2021-A-0465");
  script_xref(name:"IAVA", value:"2021-A-0473-S");
  script_xref(name:"IAVA", value:"2021-A-0468-S");

  script_name(english:"Security Updates for Microsoft Office Products (October 2021)");

  script_set_attribute(attribute:"synopsis", value:
"The Microsoft Office Products are affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The Microsoft Office Products are missing security updates.
It is, therefore, affected by multiple vulnerabilities :

  - An information disclosure vulnerability. An attacker can
    exploit this to disclose potentially sensitive
    information. (CVE-2021-40454, CVE-2021-40472)

  - A remote code execution vulnerability. An attacker can
    exploit this to bypass authentication and execute
    unauthorized arbitrary commands. (CVE-2021-40471,
    CVE-2021-40473, CVE-2021-40474, CVE-2021-40479,
    CVE-2021-40480, CVE-2021-40481, CVE-2021-40485,
    CVE-2021-40486)");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/4018332");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/4461476");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5001982");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5001985");
  # https://docs.microsoft.com/en-us/officeupdates/update-history-office-2019
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?42ab6861");
  # https://docs.microsoft.com/en-us/officeupdates/update-history-microsoft365-apps-by-date
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?fd4508ff");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released the following security updates to address this issue:  
  -KB4018332
  -KB5001982
  -KB5001985
  -KB4461476

For Office 365, Office 2016 C2R, or Office 2019, ensure automatic
updates are enabled or open any office app and manually perform an
update.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-40471");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/10/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/10/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/10/12");

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

var bulletin = 'MS21-10';
var kbs = make_list(
  '4018332',
  '4461476',
  '5001982',
  '5001985'
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

    path = hotfix_get_officeprogramfilesdir(officever:'15.0');
    path = hotfix_append_path(path:path, value:'Microsoft Office\\Office15');
    kb = '5001985';
    file = 'graph.exe';
    version = '15.0.5389.1000';
    if (hotfix_check_fversion(file:file, version:version, path:path, kb:kb, bulletin:bulletin, product:prod) == HCF_OLDER )
      vuln = TRUE;

    path = hotfix_get_officecommonfilesdir(officever:'15.0');
    path = hotfix_append_path(path:path, value:'Microsoft Shared\\Office15');
    kb = '4018332';
    file = 'riched20.dll';
    version = '15.0.5389.1000';
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
    if (hotfix_check_fversion(file:'graph.exe', version:'16.0.5227.1000', channel:'MSI', channel_product:'Office', path:path, kb:'5001982', bulletin:bulletin, product:prod) == HCF_OLDER)
      vuln = TRUE;

    path = hotfix_get_officecommonfilesdir(officever:'16.0');
    path = hotfix_append_path(path:path, value:'Microsoft Shared\\Office16');

    # MSI riched20.dll
    if (hotfix_check_fversion(file:'riched20.dll', version:'16.0.5227.1000', channel:'MSI', channel_product:'Office', path:path, kb:'4461476', bulletin:bulletin, product:prod) == HCF_OLDER)
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

