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
  script_id(134416);
  script_version("1.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/06");

  script_cve_id(
    "CVE-2020-0850",
    "CVE-2020-0851",
    "CVE-2020-0852",
    "CVE-2020-0855",
    "CVE-2020-0892",
    "CVE-2020-7080",
    "CVE-2020-7081",
    "CVE-2020-7082",
    "CVE-2020-7083",
    "CVE-2020-7084",
    "CVE-2020-7085"
  );
  script_xref(name:"MSKB", value:"4484237");
  script_xref(name:"MSFT", value:"MS20-4484237");
  script_xref(name:"CEA-ID", value:"CEA-2020-0036");

  script_name(english:"Security Updates for Microsoft Office Products (March 2020)");

  script_set_attribute(attribute:"synopsis", value:
"The Microsoft Office Products are affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The Microsoft Office Products are missing security updates.
It is, therefore, affected by multiple vulnerabilities :

  - A remote code execution vulnerability exists in
    Microsoft Word software when it fails to properly handle
    objects in memory. An attacker who successfully
    exploited the vulnerability could use a specially
    crafted file to perform actions in the security context
    of the current user. For example, the file could then
    take actions on behalf of the logged-on user with the
    same permissions as the current user.  (CVE-2020-0850,
    CVE-2020-0851, CVE-2020-0855, CVE-2020-0892)

  - A remote code execution vulnerability exists in
    Microsoft Word software when it fails to properly handle
    objects in memory. An attacker who successfully
    exploited the vulnerability could use a specially
    crafted file to perform actions in the security context
    of the current user. For example, the file could then
    take actions on behalf of the logged-on user with the
    same permissions as the current user.  (CVE-2020-0852)

  - Remote code execution vulnerabilities exist in Microsoft 
    products that utilize the FBX library when processing 
    specially crafted 3D content. An attacker who 
    successfully exploited these vulnerabilities could gain 
    the same user rights as the local user. (CVE-2020-7080, 
    CVE-2020-7081, CVE-2020-7082, CVE-2020-7083, 
    CVE-2020-7084, CVE-2020-7085)");
  # https://support.microsoft.com/en-us/help/4484237/security-update-for-office-2010-march-10-2020
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e59db2e7");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released KB4484237 to address this issue for 
Office 2010. And for Office 365, Office 2016 C2R, or Office 
2019, ensure automatic updates are enabled or open any office 
app and manually perform an update.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-7085");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2020-7082");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/03/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/03/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/03/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:office");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2020-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

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

bulletin = 'MS20-03';
kbs = make_list(
  '4484237'  # Office 2010 SP2 wwlibcxm.dll
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
    kb = '4484237';
    file = 'wwlibcxm.dll';
    version = '14.0.7246.5000';
    if (hotfix_check_fversion(file:file, version:version, path:path, kb:kb, bulletin:bulletin, product:prod) == HCF_OLDER)
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
