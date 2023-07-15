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
  script_id(130913);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/06/10");

  script_cve_id(
    "CVE-2019-1402",
    "CVE-2019-1446",
    "CVE-2019-1448",
    "CVE-2019-1449"
  );
  script_xref(name:"MSKB", value:"4484152");
  script_xref(name:"MSKB", value:"4484160");
  script_xref(name:"MSKB", value:"4484148");
  script_xref(name:"MSKB", value:"4484127");
  script_xref(name:"MSKB", value:"4484113");
  script_xref(name:"MSKB", value:"4484119");
  script_xref(name:"MSFT", value:"MS19-4484152");
  script_xref(name:"MSFT", value:"MS19-4484160");
  script_xref(name:"MSFT", value:"MS19-4484148");
  script_xref(name:"MSFT", value:"MS19-4484127");
  script_xref(name:"MSFT", value:"MS19-4484113");
  script_xref(name:"MSFT", value:"MS19-4484119");

  script_name(english:"Security Updates for Microsoft Office Products (November 2019)");

  script_set_attribute(attribute:"synopsis", value:
"The Microsoft Office Products are affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The Microsoft Office Products are missing security updates.
It is, therefore, affected by multiple vulnerabilities :

  - An information disclosure vulnerability exists in
    Microsoft Office software when the software fails to
    properly handle objects in memory. An attacker who
    successfully exploited this vulnerability could obtain
    information to further compromise the users system.
    (CVE-2019-1402)

  - A remote code execution vulnerability exists in
    Microsoft Excel software when the software fails to
    properly handle objects in memory. An attacker who
    successfully exploited the vulnerability could run
    arbitrary code in the context of the current user. If
    the current user is logged on with administrative user
    rights, an attacker could take control of the affected
    system. An attacker could then install programs; view,
    change, or delete data; or create new accounts with full
    user rights.  (CVE-2019-1448)

  - A security feature bypass vulnerability exists in the
    way that Office Click-to-Run (C2R) components handle a
    specially crafted file, which could lead to a standard
    user, any AppContainer sandbox, and Office LPAC
    Protected View to escalate privileges to SYSTEM.
    (CVE-2019-1449)

  - An information disclosure vulnerability exists when
    Microsoft Excel improperly discloses the contents of its
    memory. An attacker who exploited the vulnerability
    could use the information to compromise the users
    computer or data.  (CVE-2019-1446)");
  # https://support.microsoft.com/en-us/help/4484152/security-update-for-office-2013-november-12-2019
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?7899bb59");
  # https://support.microsoft.com/en-us/help/4484160/security-update-for-office-2010-november-12-2019
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?9ea2af0a");
  # https://support.microsoft.com/en-us/help/4484148/security-update-for-office-2016-november-12-2019
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f2f9db6d");
  # https://support.microsoft.com/en-us/help/4484127/security-update-for-office-2010-november-12-2019
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?cd218f71");
  # https://support.microsoft.com/en-us/help/4484113/security-update-for-office-2016-november-12-2019
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?3ff227fc");
  # https://support.microsoft.com/en-us/help/4484119/security-update-for-office-2013-november-12-2019
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?99349609");
  # https://docs.microsoft.com/en-us/officeupdates/update-history-office365-proplus-by-date
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c6fc9b1b");
  # https://docs.microsoft.com/en-us/officeupdates/update-history-office-2019
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?42ab6861");
  # https://support.office.com/en-us/article/install-office-updates-2ab296f3-7f03-43a2-8e50-46de917611c5
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?7b126882");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released the following security updates to address this issue:  
  -KB4484152
  -KB4484160
  -KB4484148
  -KB4484127
  -KB4484113
  -KB4484119

For Office 365, Office 2016 C2R, or Office 2019, ensure automatic
updates are enabled or open any office app and manually perform an
update.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-1449");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/11/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/11/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/11/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:office");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2019-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

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

get_kb_item_or_exit("SMB/MS_Bulletin_Checks/Possible");

bulletin = "MS19-11";
kbs = make_list(
  "4484127", # Office 2010 SP2
  "4484160", # Office 2010 SP2
  "4484152", # Office 2013 SP1
  "4484119", # Office 2013 SP1
  "4484148", # Office 2016
  "4484113"  # Office 2016
);

if (get_kb_item("Host/patch_management_checks"))
  hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

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
    kb = "4484160";
    file = "graph.exe";
    version = "14.0.7241.5000";
    if (hotfix_check_fversion(file:file, version:version, path:path, kb:kb, bulletin:bulletin, product:prod) == HCF_OLDER)
      vuln = TRUE;

    path = hotfix_get_officecommonfilesdir(officever:"14.0");
    path = hotfix_append_path(path:path, value:"Microsoft Shared\Office14");
    kb = "4484127";
    file = "acecore.dll";
    version = "14.0.7241.5000";
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
    kb = "4484152";
    file = "graph.exe";
    version = "15.0.5189.1000";
    if (hotfix_check_fversion(file:file, version:version, path:path, kb:kb, bulletin:bulletin, product:prod) == HCF_OLDER )
      vuln = TRUE;

    path = hotfix_get_officecommonfilesdir(officever:"15.0");
    path = hotfix_append_path(path:path, value:"Microsoft Shared\Office15");
    kb = "4484119";
    file = "acecore.dll";
    version = "15.0.5189.1000";
    if (hotfix_check_fversion(file:file, version:version, path:path, kb:kb, bulletin:bulletin, product:prod) == HCF_OLDER )
      vuln = TRUE;
  }
}

# Office 2016 / 2019 / C2R
if (office_vers["16.0"])
{
  office_sp = get_kb_item("SMB/Office/2016/SP");
  if (!isnull(office_sp) && office_sp == 0)
  {
    prod = "Microsoft Office 2016";

    # MSI graph.exe
    path = hotfix_get_officeprogramfilesdir(officever:"16.0");
    path = hotfix_append_path(path:path, value:"Microsoft Office\Office16");
    kb = "4484148";
    file = "graph.exe";
    version = "16.0.4927.1000";
    if (hotfix_check_fversion(file:file, version:version, channel:"MSI", channel_product:"Office", path:path, kb:kb, bulletin:bulletin, product:prod) == HCF_OLDER)
      vuln = TRUE;

    # MSI acecore.dll
    path = hotfix_get_officecommonfilesdir(officever:"16.0");
    path = hotfix_append_path(path:path, value:"Microsoft Shared\Office16");
    kb = "4484113";
    file = "acecore.dll";
    version = "16.0.4927.1000";
    if (hotfix_check_fversion(file:file, version:version, channel:"MSI", channel_product:"Office", path:path, kb:kb, bulletin:bulletin, product:prod) == HCF_OLDER)
      vuln = TRUE;

    path = hotfix_get_officecommonfilesdir(officever:'16.0');
    prod2019 = 'Microsoft Office 2019';
    mso_dll_path = hotfix_append_path(path:path, value:'Microsoft Shared\\Office16');
    c2r_path = mso_dll_path;
  }
}
if (vuln)
{
  replace_kb_item(name:"SMB/Missing/"+bulletin, value:TRUE);
  hotfix_security_hole();
  hotfix_check_fversion_end();
  exit(0);
}
else
{
  hotfix_check_fversion_end();
  audit(AUDIT_HOST_NOT, "affected");
}

