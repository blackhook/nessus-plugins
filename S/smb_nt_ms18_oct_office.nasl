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
  script_id(118010);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/06/10");

  script_cve_id("CVE-2018-8501", "CVE-2018-8502", "CVE-2018-8504");
  script_xref(name:"MSKB", value:"4461445");
  script_xref(name:"MSKB", value:"4461437");
  script_xref(name:"MSKB", value:"4092437");
  script_xref(name:"MSKB", value:"4092483");
  script_xref(name:"MSFT", value:"MS18-4461445");
  script_xref(name:"MSFT", value:"MS18-4461437");
  script_xref(name:"MSFT", value:"MS18-4092437");
  script_xref(name:"MSFT", value:"MS18-4092483");

  script_name(english:"Security Updates for Microsoft Office Products (October 2018)");

  script_set_attribute(attribute:"synopsis", value:
"The Microsoft Office Products are affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The Microsoft Office Products are missing security updates.
It is, therefore, affected by multiple vulnerabilities :

  - A remote code execution vulnerability exists in
    Microsoft Word software when the software fails to
    properly handle objects in Protected View. An attacker
    who successfully exploited the vulnerability could run
    arbitrary code in the context of the current user. If
    the current user is logged on with administrative user
    rights, an attacker could take control of the affected
    system. An attacker could then install programs; view,
    change, or delete data; or create new accounts with full
    user rights.  (CVE-2018-8504)

  - A remote code execution vulnerability exists in
    Microsoft PowerPoint software when the software fails to
    properly handle objects in Protected View. An attacker
    who successfully exploited the vulnerability could run
    arbitrary code in the context of the current user. If
    the current user is logged on with administrative user
    rights, an attacker could take control of the affected
    system. An attacker could then install programs; view,
    change, or delete data; or create new accounts with full
    user rights.  (CVE-2018-8501)

  - A remote code execution vulnerability exists in
    Microsoft Excel software when the software fails to
    properly handle objects in Protected View. An attacker
    who successfully exploited the vulnerability could run
    arbitrary code in the context of the current user. If
    the current user is logged on with administrative user
    rights, an attacker could take control of the affected
    system. An attacker could then install programs; view,
    change, or delete data; or create new accounts with full
    user rights.  (CVE-2018-8502)");
  # https://support.microsoft.com/en-us/help/4461445/description-of-the-security-update-for-office-2013-october-9-2018
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?25445b71");
  # https://support.microsoft.com/en-us/help/4461437/description-of-the-security-update-for-office-2016-october-9-2018
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?53432b66");
  # https://support.microsoft.com/en-us/help/4092437/description-of-the-security-update-for-office-2010-october-9-2018
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?730447ea");
  # https://support.microsoft.com/en-us/help/4092483/description-of-the-security-update-for-office-2010-october-9-2018
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?6093b2d8");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released the following security updates to address this issue:  
  -KB4461445
  -KB4461437
  -KB4092437
  -KB4092483");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-8501");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/10/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/10/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/10/09");

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

bulletin = "MS18-10";
kbs = make_list(
  '4092483', # Office 2010 SP2
  '4092437', # Office 2010 SP2
  '4461445', # Office 2013 SP1
  '4461437'  # Office 2016
);

if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

get_kb_item_or_exit("SMB/Registry/Enumerated", exit_code:1);

vuln = FALSE;
port = kb_smb_transport();

office_vers = hotfix_check_office_version();

####################################################################
# Office 2010 SP2
####################################################################
if (office_vers["14.0"])
{
  office_sp = get_kb_item("SMB/Office/2010/SP");
  if (!isnull(office_sp) && office_sp == 2)
  {
    prod = "Microsoft Office 2010 SP2";

    path = hotfix_get_officecommonfilesdir(officever:"14.0");
    path = hotfix_append_path(
      path  : path,
      value : "Microsoft Shared\Office14"
    );
    file = "mso.dll";
    kb = "4092483";
    if (hotfix_check_fversion(file:file, version:"14.0.7214.5000", path:path, kb:kb, bulletin:bulletin, product:prod) == HCF_OLDER)
      vuln = TRUE;

    # wwlibcxm.dll only exists if KB2428677 is installed
    path = hotfix_get_officeprogramfilesdir(officever:"14.0");
    file = "wwlibcxm.dll";
    kb = "4092437";
    if (hotfix_check_fversion(file:file, version:"14.0.7214.5000", path:path, kb:kb, bulletin:bulletin, product:prod) == HCF_OLDER)
      vuln = TRUE;
  }
}

####################################################################
# Office 2013 SP1
####################################################################
if (office_vers["15.0"])
{
  office_sp = get_kb_item("SMB/Office/2013/SP");
  if (!isnull(office_sp) && office_sp == 1)
  {
    prod = "Microsoft Office 2013 SP1";

    path = hotfix_get_officecommonfilesdir(officever:"15.0");
    path = hotfix_append_path(
      path  : path,
      value : "Microsoft Shared\Office15"
    );

    if (hotfix_check_fversion(file:"mso.dll", version:"15.0.5075.1001", path:path, kb:"4461445", bulletin:bulletin, product:prod) == HCF_OLDER)
      vuln = TRUE;
  }
}

####################################################################
# Office 2016 / 2019
####################################################################
if (office_vers["16.0"])
{
  office_sp = get_kb_item("SMB/Office/2016/SP");
  if (!isnull(office_sp) && office_sp == 0)
  {
    prod = "Microsoft Office 2016";

    path = hotfix_get_officecommonfilesdir(officever:"16.0");
    msi_path = hotfix_append_path(path: path, value : "Microsoft Shared\Office16");
    c2r_path = msi_path;
    file = "mso.dll";
    kb = "4461437";
    if (
      hotfix_check_fversion(file:file, version:"16.0.4756.1000", channel:"MSI", channel_product:"Office", path:msi_path, kb:kb, bulletin:bulletin, product:prod) == HCF_OLDER
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
