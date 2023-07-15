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
  script_id(131937);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/06/10");

  script_cve_id(
    "CVE-2019-1400",
    "CVE-2019-1461",
    "CVE-2019-1462",
    "CVE-2019-1463",
    "CVE-2019-1464"
  );
  script_xref(name:"MSKB", value:"4484182");
  script_xref(name:"MSKB", value:"4484180");
  script_xref(name:"MSKB", value:"4484186");
  script_xref(name:"MSKB", value:"4484193");
  script_xref(name:"MSKB", value:"4484192");
  script_xref(name:"MSKB", value:"4475598");
  script_xref(name:"MSKB", value:"4484184");
  script_xref(name:"MSFT", value:"MS19-4484182");
  script_xref(name:"MSFT", value:"MS19-4484180");
  script_xref(name:"MSFT", value:"MS19-4484186");
  script_xref(name:"MSFT", value:"MS19-4484193");
  script_xref(name:"MSFT", value:"MS19-4484192");
  script_xref(name:"MSFT", value:"MS19-4475598");
  script_xref(name:"MSFT", value:"MS19-4484184");

  script_name(english:"Security Updates for Microsoft Office Products (December 2019)");

  script_set_attribute(attribute:"synopsis", value:
"The Microsoft Office Products are affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The Microsoft Office Products are missing security updates.
It is, therefore, affected by multiple vulnerabilities :

  - An information disclosure vulnerability exists when
    Microsoft Excel improperly discloses the contents of its
    memory. An attacker who exploited the vulnerability
    could use the information to compromise the users
    computer or data.  (CVE-2019-1464)

  - A denial of service vulnerability exists in Microsoft
    Word software when the software fails to properly handle
    objects in memory. An attacker who successfully
    exploited the vulnerability could cause a remote denial
    of service against a system. Exploitation of the
    vulnerability requires that a specially crafted document
    be sent to a vulnerable user. The security update
    addresses the vulnerability by correcting how Microsoft
    Word handles objects in memory. (CVE-2019-1461)

  - An information disclosure vulnerability exists in
    Microsoft Access software when the software fails to
    properly handle objects in memory. An attacker who
    successfully exploited this vulnerability could obtain
    information to further compromise the users system.
    (CVE-2019-1400, CVE-2019-1463)

  - A remote code execution vulnerability exists in
    Microsoft PowerPoint software when the software fails to
    properly handle objects in memory. An attacker who
    successfully exploited the vulnerability could run
    arbitrary code in the context of the current user. If
    the current user is logged on with administrative user
    rights, an attacker could take control of the affected
    system. An attacker could then install programs; view,
    change, or delete data; or create new accounts with full
    user rights.  (CVE-2019-1462)");
  # https://support.microsoft.com/en-us/help/4484182/security-update-for-office-2016-december-10-2019
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a36df0be");
  # https://support.microsoft.com/en-us/help/4484180/security-update-for-office-2016-december-10-2019
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e333f874");
  # https://support.microsoft.com/en-us/help/4484186/security-update-for-office-2013-december-10-2019
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?985277e6");
  # https://support.microsoft.com/en-us/help/4484193/security-update-for-office-2010-december-10-2019
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?6044cfc4");
  # https://support.microsoft.com/en-us/help/4484192/security-update-for-office-2010-december-10-2019
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d1d98b2f");
  # https://support.microsoft.com/en-us/help/4475598/security-update-for-office-2010-december-10-2019
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?77cf90ea");
  # https://support.microsoft.com/en-us/help/4484184/security-update-for-office-2013-december-10-2019
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?085ed15a");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released the following security updates to address this issue:  
  -KB4484182
  -KB4484180
  -KB4484186
  -KB4484193
  -KB4484192
  -KB4475598
  -KB4484184

For Office 365, Office 2016 C2R, or Office 2019, ensure automatic
updates are enabled or open any office app and manually perform an
update.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-1462");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/12/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/12/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/12/10");

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

bulletin = "MS19-12";
kbs = make_list(
  "4484193", # Office 2010 SP2
  "4475598", # Office 2010 SP2
  "4484192", # Office 2010 SP2
  "4484186", # Office 2013 SP1
  "4484184", # Office 2013 SP1
  "4484180", # Office 2016
  "4484182"  # Office 2016
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

    path = hotfix_get_officecommonfilesdir(officever:"14.0");
    path = hotfix_append_path(path:path, value:"Microsoft Shared\Office14");
    kb = "4484193";
    file = "acecore.dll";
    version = "14.0.7243.5000";
    if (hotfix_check_fversion(file:file, version:version, path:path, kb:kb, bulletin:bulletin, product:prod) == HCF_OLDER)
      vuln = TRUE;

    # wwlibcxm.dll only exists if KB2428677 is installed
    path = hotfix_get_officeprogramfilesdir(officever:"14.0");
    path = hotfix_append_path(path:path, value:"Microsoft Office\Office14");
    kb = "4475598";
    file = "wwlibcxm.dll";
    version = "14.0.7243.5000";
    if (hotfix_check_fversion(file:file, version:version, path:path, kb:kb, bulletin:bulletin, product:prod) == HCF_OLDER)
      vuln = TRUE;

    path = hotfix_get_officeprogramfilesdir(officever:"14.0");
    path = hotfix_append_path(path:path, value:"Microsoft Office\Office14");
    kb = "4484192";
    file = "graph.exe";
    version = "14.0.7243.5000";
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

    path = hotfix_get_officecommonfilesdir(officever:"15.0");
    path = hotfix_append_path(path:path, value:"Microsoft Shared\Office15");
    kb = "4484186";
    file = "acecore.dll";
    version = "15.0.5197.1000";
    if (hotfix_check_fversion(file:file, version:version, path:path, kb:kb, bulletin:bulletin, product:prod) == HCF_OLDER )
      vuln = TRUE;

    path = hotfix_get_officeprogramfilesdir(officever:"15.0");
    path = hotfix_append_path(path:path, value:"Microsoft Office\Office15");
    kb = "4484184";
    file = "graph.exe";
    version = "15.0.5197.1000";
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

    # MSI acecore.dll
    path = hotfix_get_officecommonfilesdir(officever:"16.0");
    path = hotfix_append_path(path:path, value:"Microsoft Shared\Office16");
    kb = "4484180";
    file = "acecore.dll";
    version = "16.0.4939.1000";
    if (hotfix_check_fversion(file:file, version:version, channel:"MSI", channel_product:"Office", path:path, kb:kb, bulletin:bulletin, product:prod) == HCF_OLDER)
      vuln = TRUE;

    # MSI graph.exe
    path = hotfix_get_officeprogramfilesdir(officever:"16.0");
    path = hotfix_append_path(path:path, value:"Microsoft Office\Office16");
    kb = "4484182";
    file = "graph.exe";
    version = "16.0.4939.1000";
    if (hotfix_check_fversion(file:file, version:version, channel:"MSI", channel_product:"Office", path:path, kb:kb, bulletin:bulletin, product:prod) == HCF_OLDER)
      vuln = TRUE;
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

