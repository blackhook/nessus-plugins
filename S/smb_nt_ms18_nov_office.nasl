#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from the Microsoft Security Updates API. The text
# itself is copyright (C) Microsoft Corporation.
#
include("compat.inc");

if (description)
{
  script_id(118923);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/06/10");

  script_cve_id("CVE-2018-8539", "CVE-2018-8573", "CVE-2018-8577");
  script_bugtraq_id(105834, 105835, 105836);
  script_xref(name:"MSKB", value:"3114565");
  script_xref(name:"MSKB", value:"4022232");
  script_xref(name:"MSKB", value:"4022237");
  script_xref(name:"MSKB", value:"4032218");
  script_xref(name:"MSKB", value:"4461524");
  script_xref(name:"MSFT", value:"MS18-3114565");
  script_xref(name:"MSFT", value:"MS18-4022232");
  script_xref(name:"MSFT", value:"MS18-4022237");
  script_xref(name:"MSFT", value:"MS18-4032218");
  script_xref(name:"MSFT", value:"MS18-4461524");

  script_name(english:"Security Updates for Microsoft Office Products (November 2018)");

  script_set_attribute(attribute:"synopsis", value:
"The Microsoft Office Products are affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The Microsoft Office Products are missing security updates.
It is, therefore, affected by multiple vulnerabilities:

  - A remote code execution vulnerability exists in Microsoft Word
    software when it fails to properly handle objects in memory. An
    attacker who successfully exploited the vulnerability could use a
    specially crafted file to perform actions in the security context
    of the current user. For example, the file could then take
    actions on behalf of the logged-on user with the same permissions
    as the current user. (CVE-2018-8539)

  - A remote code execution vulnerability exists in Microsoft Word
    software when it fails to properly handle objects in memory. An
    attacker who successfully exploited the vulnerability could use 
    specially crafted file to perform actions in the security context
    of the current user. For example, the file could then take
    actions on behalf of the logged-on user with the same permissions
    as the current user. (CVE-2018-8573)

  - A remote code execution vulnerability exists in Microsoft Excel
    software when the software fails to properly handle objects in
    memory. An attacker who successfully exploited the vulnerability
    could run arbitrary code in the context of the current user. If
    the current user is logged on with administrative user rights, an
    attacker could take control of the affected system. An attacker
    could then install programs; view, change, or delete data; or
    create new accounts with full user rights. Users whose accounts
    are configured to have fewer user rights on the system could be
    less impacted than users who operate with administrative user
    rights. (CVE-2018-8577)");
  # https://support.microsoft.com/en-us/help/3114565/description-of-the-security-update-for-office-2010-november-13-2018
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b54ec653");
  # https://support.microsoft.com/en-us/help/4461524/description-of-the-security-update-for-office-2010-november-13-2018
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?40ae07b8");
  # https://support.microsoft.com/en-us/help/4022237/description-of-the-security-update-for-office-2013-november-13-2018
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?bf1d296c");
  # https://support.microsoft.com/en-us/help/4022232/description-of-the-security-update-for-office-2016-november-13-2018
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?33c6fe77");
  # https://support.microsoft.com/en-us/help/4032218/description-of-the-security-update-for-office-2010-november-13-2018
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c40d64c8");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released the following security updates to address this issue:
  -KB3114565
  -KB4022232
  -KB4022237
  -KB4032218
  -KB4461524");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-8539");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/11/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/11/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/11/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:office");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2018-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("office_installed.nasl", "smb_hotfixes.nasl", "ms_bulletin_checks_possible.nasl");
  script_require_keys("SMB/MS_Bulletin_Checks/Possible");
  script_require_ports(139, 445, "Host/patch_management_checks");

  exit(0);
}

include("audit.inc");
include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");
include("smb_reg_query.inc");
include("misc_func.inc");
include("install_func.inc");

global_var vuln;

get_kb_item_or_exit("SMB/MS_Bulletin_Checks/Possible");

bulletin = "MS18-11";
kbs = make_list(
  '3114565', # Office 2010 SP2
  '4032218', # Office 2010 SP2
  '4461524', # Office 2010 SP2
  '4022237', # Office 2013 SP1
  '4022232'  # Office 2016
);

if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

get_kb_item_or_exit("SMB/Registry/Enumerated", exit_code:1);

vuln = FALSE;
port = kb_smb_transport();

office_vers = hotfix_check_office_version();

# Office 2010 SP2
if (office_vers["14.0"])
{
  office_sp = get_kb_item("SMB/Office/2010/SP");
  if (!isnull(office_sp) && office_sp == 2)
  {
    prod = "Microsoft Office 2010 SP2";

    path = hotfix_get_officeprogramfilesdir(officever:"14.0");
    path = hotfix_append_path(path:path, value:"Microsoft Office\Office14");
    kb = "4032218";
    file = "graph.exe";
    version = "14.0.7224.5000";
    if (hotfix_check_fversion(file:file, version:version, path:path, kb:kb, bulletin:bulletin, product:prod) == HCF_OLDER)
      vuln = TRUE;

    path = hotfix_get_officecommonfilesdir(officever:"14.0");
    path = hotfix_append_path(path:path, value:"Microsoft Shared\Office14");
    kb = "3114565";
    file = "msptls.dll";
    version = "14.0.7224.5000";
    if (hotfix_check_fversion(file:file, version:version, path:path, kb:kb, bulletin:bulletin, product:prod) == HCF_OLDER)
      vuln = TRUE;

    # wwlibcxm.dll only exists if KB2428677 is installed
    path = hotfix_get_officeprogramfilesdir(officever:"14.0");
    kb = "4461524";
    file = "wwlibcxm.dll";
    version = "14.0.7224.5000";
    if (hotfix_check_fversion(file:file, version:version, path:path, kb:kb, bulletin:bulletin, product:prod) == HCF_OLDER)
      vuln = TRUE;
  }
}

# Office 2013 SP1
if (office_vers["15.0"])
{
  office_sp = get_kb_item("SMB/Office/2013/SP");
  if (!isnull(office_sp) && office_sp == 1)
  {
    prod = "Microsoft Office 2013 SP1";

    path = hotfix_get_officeprogramfilesdir(officever:"15.0");
    path = hotfix_append_path(path:path, value:"Microsoft Office\Office15");
    kb = "4022237";
    file = "graph.exe";
    version = "15.0.5085.1000";
    if (hotfix_check_fversion(file:file, version:version, path:path, kb:kb, bulletin:bulletin, product:prod) == HCF_OLDER)
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

    path = hotfix_get_officeprogramfilesdir(officever:"16.0");
    msi_path = hotfix_append_path(path: path, value : "Microsoft Office\Office16");
    c2r_path = hotfix_append_path(path: path, value : "Microsoft Office\root\Office16");
    file = "graph.exe";
    kb = "4022232";
    if (
      hotfix_check_fversion(file:file, version:"16.0.4771.1000", channel:"MSI", channel_product:"Office", path:msi_path, kb:kb, bulletin:bulletin, product:prod) == HCF_OLDER
    )
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
