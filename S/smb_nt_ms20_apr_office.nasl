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
  script_id(135476);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/06/10");

  script_cve_id(
    "CVE-2020-0760",
    "CVE-2020-0906",
    "CVE-2020-0961",
    "CVE-2020-0979",
    "CVE-2020-0980",
    "CVE-2020-0991"
  );
  script_xref(name:"MSKB", value:"3128012");
  script_xref(name:"MSKB", value:"3203462");
  script_xref(name:"MSKB", value:"4011104");
  script_xref(name:"MSKB", value:"4484117");
  script_xref(name:"MSKB", value:"4484126");
  script_xref(name:"MSKB", value:"4484214");
  script_xref(name:"MSKB", value:"4484229");
  script_xref(name:"MSKB", value:"4484238");
  script_xref(name:"MSKB", value:"4484258");
  script_xref(name:"MSKB", value:"4484260");
  script_xref(name:"MSKB", value:"4484266");
  script_xref(name:"MSKB", value:"4484287");
  script_xref(name:"MSKB", value:"4484294");
  script_xref(name:"MSFT", value:"MS20-3128012");
  script_xref(name:"MSFT", value:"MS20-3203462");
  script_xref(name:"MSFT", value:"MS20-4011104");
  script_xref(name:"MSFT", value:"MS20-4484117");
  script_xref(name:"MSFT", value:"MS20-4484126");
  script_xref(name:"MSFT", value:"MS20-4484214");
  script_xref(name:"MSFT", value:"MS20-4484229");
  script_xref(name:"MSFT", value:"MS20-4484238");
  script_xref(name:"MSFT", value:"MS20-4484258");
  script_xref(name:"MSFT", value:"MS20-4484260");
  script_xref(name:"MSFT", value:"MS20-4484266");
  script_xref(name:"MSFT", value:"MS20-4484287");
  script_xref(name:"MSFT", value:"MS20-4484294");
  script_xref(name:"IAVA", value:"2020-A-0142-S");

  script_name(english:"Security Updates for Microsoft Office Products (April 2020)");

  script_set_attribute(attribute:"synopsis", value:
"The Microsoft Office Products are affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The Microsoft Office Products are missing security updates.
It is, therefore, affected by multiple vulnerabilities :

  - A remote code execution vulnerability exists when
    Microsoft Office improperly loads arbitrary type
    libraries. An attacker could then install programs;
    view, change, or delete data; or create new accounts
    with full user rights. Users whose accounts are
    configured to have fewer user rights on the system could
    be less impacted than users who operate with
    administrative user rights.  (CVE-2020-0760)

  - A remote code execution vulnerability exists in
    Microsoft Word software when it fails to properly handle
    objects in memory. An attacker who successfully
    exploited the vulnerability could use a specially
    crafted file to perform actions in the security context
    of the current user. For example, the file could then
    take actions on behalf of the logged-on user with the
    same permissions as the current user.  (CVE-2020-0980)

  - A remote code execution vulnerability exists in
    Microsoft Office software when the software fails to
    properly handle objects in memory. An attacker who
    successfully exploited the vulnerability could run
    arbitrary code in the context of the current user. If
    the current user is logged on with administrative user
    rights, an attacker could take control of the affected
    system. An attacker could then install programs; view,
    change, or delete data; or create new accounts with full
    user rights.  (CVE-2020-0991)

  - A remote code execution vulnerability exists when the
    Microsoft Office Access Connectivity Engine improperly
    handles objects in memory. An attacker who successfully
    exploited this vulnerability could execute arbitrary
    code on a victim system. An attacker could exploit this
    vulnerability by enticing a victim to open a specially
    crafted file. The update addresses the vulnerability by
    correcting the way the Microsoft Office Access
    Connectivity Engine handles objects in memory.
    (CVE-2020-0961)

  - A remote code execution vulnerability exists in
    Microsoft Excel software when the software fails to
    properly handle objects in memory. An attacker who
    successfully exploited the vulnerability could run
    arbitrary code in the context of the current user. If
    the current user is logged on with administrative user
    rights, an attacker could take control of the affected
    system. An attacker could then install programs; view,
    change, or delete data; or create new accounts with full
    user rights.  (CVE-2020-0906, CVE-2020-0979)");
  # https://support.microsoft.com/en-us/help/3128012/security-update-for-office-2016-april-14-2020
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c6907f9f");
  # https://support.microsoft.com/en-us/help/4484214/security-update-for-office-2016-april-14-2020
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?22455c7d");
  # https://support.microsoft.com/en-us/help/4484260/security-update-for-office-2013-april-14-2020
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?6758cebc");
  # https://support.microsoft.com/en-us/help/4484266/security-update-for-office-2010-april-14-2020
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?19ff4b0c");
  # https://support.microsoft.com/en-us/help/4484287/security-update-for-office-2016-april-14-2020
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?acbb3d03");
  # https://support.microsoft.com/en-us/help/4484294/security-update-for-office-2010-april-14-2020
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?5e18eb45");
  # https://support.microsoft.com/en-us/help/3203462/security-update-for-office-2010-april-14-2020
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?87117772");
  # https://support.microsoft.com/en-us/help/4484258/security-update-for-office-2016-april-14-2020
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?cc8824f1");
  # https://support.microsoft.com/en-us/help/4484126/security-update-for-office-2010-april-14-2020
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a0a366b9");
  # https://support.microsoft.com/en-us/help/4011104/security-update-for-office-2013-april-14-2020
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ee0e9939");
  # https://support.microsoft.com/en-us/help/4484117/security-update-for-office-2013-april-14-2020
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?318ce33a");
  # https://support.microsoft.com/en-us/help/4484238/security-update-for-office-2010-april-14-2020
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?872a2ed0");
  # https://support.microsoft.com/en-us/help/4484229/security-update-for-office-2013-april-14-2020
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?67e5e2db");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released security updates for Microsoft Office Products.

For Office 365, Office 2016 C2R, or Office 2019, ensure automatic
updates are enabled or open any office app and manually perform an
update.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-0991");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2020-0979");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/04/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/04/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/04/14");

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

bulletin = 'MS20-04';
kbs = make_list(
  '3203462', # Office 2010 SP2
  '4484126', # Office 2010 SP2
  '4484238', # Office 2010 SP2
  '4484266', # Office 2010 SP2
  '4484294', # Office 2010 SP2
  '4011104', # Office 2013 SP1
  '4484117', # Office 2013 SP1
  '4484229', # Office 2013 SP1
  '4484260', # Office 2013 SP1
  '3128012', # Office 2016
  '4484214', # Office 2016
  '4484287', # Office 2016
  '4484258'  # Office 2016
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

    path = hotfix_get_officecommonfilesdir(officever:'14.0');
    path = hotfix_append_path(path:path, value:'Microsoft Shared\\VBA\\VBA7');
    kb = '3203462';
    file = 'vbe7.dll';
    version = '7.0.16.45';
    if (hotfix_check_fversion(file:file, version:version, path:path, kb:kb, bulletin:bulletin, product:prod) == HCF_OLDER)
      vuln = TRUE;

    path = hotfix_get_officecommonfilesdir(officever:'14.0');
    path = hotfix_append_path(path:path, value:'Microsoft Shared\\OFFICE14');
    kb = '4484126';
    file = 'mso.dll';
    version = '14.0.7248.5000';
    if (hotfix_check_fversion(file:file, version:version, path:path, kb:kb, bulletin:bulletin, product:prod) == HCF_OLDER)
      vuln = TRUE;

    path = hotfix_get_officecommonfilesdir(officever:'14.0');
    path = hotfix_append_path(path:path, value:'Microsoft Shared\\OFFICE14');
    kb = '4484238';
    file = 'acecore.dll';
    version = '14.0.7248.5000';
    if (hotfix_check_fversion(file:file, version:version, path:path, kb:kb, bulletin:bulletin, product:prod) == HCF_OLDER)
      vuln = TRUE;

    path = hotfix_get_officeprogramfilesdir(officever:'14.0');
    path = hotfix_append_path(path:path, value:'Microsoft Office\\Office14');
    kb = '4484266';
    file = 'graph.exe';
    version = '14.0.7248.5000';
    if (hotfix_check_fversion(file:file, version:version, path:path, kb:kb, bulletin:bulletin, product:prod) == HCF_OLDER)
      vuln = TRUE;

    # wwlibcxm.dll only exists if KB2428677 is installed
    path = hotfix_get_officeprogramfilesdir(officever:'14.0');
    path = hotfix_append_path(path:path, value:'Microsoft Office\\Office14');
    kb = '4484294';
    file = 'wwlibcxm.dll';
    version = '14.0.7248.5000';
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
    kb = '4011104';
    file = 'vbe7.dll';
    version = '7.1.10.96';
    if (hotfix_check_fversion(file:file, version:version, path:path, kb:kb, bulletin:bulletin, product:prod) == HCF_OLDER )
      vuln = TRUE;

    path = hotfix_get_officecommonfilesdir(officever:'15.0');
    path = hotfix_append_path(path:path, value:'Microsoft Shared\\OFFICE15');
    kb = '4484117';
    file = 'mso.dll';
    version = '15.0.5233.1000';
    if (hotfix_check_fversion(file:file, version:version, path:path, kb:kb, bulletin:bulletin, product:prod) == HCF_OLDER )
      vuln = TRUE;

    path = hotfix_get_officecommonfilesdir(officever:'15.0');
    path = hotfix_append_path(path:path, value:'Microsoft Shared\\OFFICE15');
    kb = '4484229';
    file = 'acecore.dll';
    version = '15.0.5233.1000';
    if (hotfix_check_fversion(file:file, version:version, path:path, kb:kb, bulletin:bulletin, product:prod) == HCF_OLDER )
      vuln = TRUE;

    path = hotfix_get_officeprogramfilesdir(officever:'15.0');
    path = hotfix_append_path(path:path, value:'Microsoft Office\\Office15');
    kb = '4484260';
    file = 'graph.exe';
    version = '15.0.5233.1000';
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

    path = hotfix_get_officecommonfilesdir(officever:'16.0');
    path = hotfix_append_path(path:path, value:'Microsoft Shared\\VBA\\VBA7.1');
    kb = '3128012';
    file = 'vbe7.dll';
    version = '7.1.10.96';
    if (hotfix_check_fversion(file:file, version:version, channel:'MSI', channel_product:'Office', path:path, kb:kb, bulletin:bulletin, product:prod) == HCF_OLDER)
      vuln = TRUE;

    path = hotfix_get_officecommonfilesdir(officever:'16.0');
    path = hotfix_append_path(path:path, value:'Microsoft Shared\\OFFICE16');
    kb = '4484214';
    file = 'mso.dll';
    version = '16.0.4993.1002';
    if (hotfix_check_fversion(file:file, version:version, channel:'MSI', channel_product:'Office', path:path, kb:kb, bulletin:bulletin, product:prod) == HCF_OLDER)
      vuln = TRUE;

    path = hotfix_get_officecommonfilesdir(officever:'16.0');
    path = hotfix_append_path(path:path, value:'Microsoft Shared\\OFFICE16');
    kb = '4484287';
    file = 'acecore.dll';
    version = '16.0.4993.1000';
    if (hotfix_check_fversion(file:file, version:version, channel:'MSI', channel_product:'Office', path:path, kb:kb, bulletin:bulletin, product:prod) == HCF_OLDER)
      vuln = TRUE;

    path = hotfix_get_officeprogramfilesdir(officever:'16.0');
    path = hotfix_append_path(path:path, value:'Microsoft Office\\Office16');
    kb = '4484258';
    file = 'graph.exe';
    version = '16.0.4993.1000';
    if (hotfix_check_fversion(file:file, version:version, channel:'MSI', channel_product:'Office', path:path, kb:kb, bulletin:bulletin, product:prod) == HCF_OLDER)
      vuln = TRUE;

    prod2019 = 'Microsoft Office 2019';
    path = hotfix_get_officeprogramfilesdir(officever:'16.0');
    path = hotfix_append_path(path:path, value:'Microsoft Office\\root\\Office16');
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
