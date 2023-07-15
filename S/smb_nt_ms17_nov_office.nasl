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
  script_id(104557);
  script_version("1.19");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/25");

  script_cve_id("CVE-2017-11854", "CVE-2017-11882");
  script_bugtraq_id(101746, 101757);
  script_xref(name:"MSKB", value:"3162047");
  script_xref(name:"MSKB", value:"4011268");
  script_xref(name:"MSKB", value:"4011604");
  script_xref(name:"MSKB", value:"4011262");
  script_xref(name:"MSKB", value:"4011618");
  script_xref(name:"MSFT", value:"MS17-3162047");
  script_xref(name:"MSFT", value:"MS17-4011268");
  script_xref(name:"MSFT", value:"MS17-4011604");
  script_xref(name:"MSFT", value:"MS17-4011262");
  script_xref(name:"MSFT", value:"MS17-4011618");
  script_xref(name:"IAVA", value:"2017-A-0337-S");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/05/03");

  script_name(english:"Security Updates for Microsoft Office Products (November 2017)");

  script_set_attribute(attribute:"synopsis", value:
"The Microsoft Office Products are affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The Microsoft Office Products are missing security updates.
It is, therefore, affected by multiple vulnerabilities :

  - Microsoft has released an update for Microsoft Office that
    provides enhanced security as a defense-in-depth measure.

  - A remote code execution vulnerability exists in Microsoft Office
    software when the software fails to properly handle objects in
    memory. An attacker who successfully exploited the vulnerability
    could run arbitrary code in the context of the current user. If
    the current user is logged on with administrative user rights, an
    attacker could take control of the affected system. An attacker
    could then install programs; view, change, or delete data; or
    create new accounts with full user rights. Users whose accounts
    are configured to have fewer user rights on the system could be
    less impacted than users who operate with administrative user
    rights. (CVE-2017-11854)

  - A remote code execution vulnerability exists in Microsoft Office
    software when the software fails to properly handle objects in
    memory. An attacker who successfully exploited the vulnerability
    could run arbitrary code in the context of the current user. If
    the current user is logged on with administrative user rights, an
    attacker could take control of the affected system. An attacker
    could then install programs; view, change, or delete data; or
    create new accounts with full user rights. Users whose accounts
    are configured to have fewer user rights on the system could be
    less impacted than users who operate with administrative user
    rights. (CVE-2017-11882)");
  # https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/ADV170020
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0f1b55d1");
  # https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/CVE-2017-11854
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?7c504489");
  # https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/CVE-2017-11882
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?df348bb4");
  # https://support.microsoft.com/en-us/help/3162047/descriptionofthesecurityupdateforoffice2013november14-2017
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?4a238ff7");
  # https://support.microsoft.com/en-us/help/4011276/descriptionofthesecurityupdatefor2007microsoftofficesuitenovember14-20
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b3ad665b");
  # https://support.microsoft.com/en-us/help/4011262/descriptionofthesecurityupdateforoffice2016november14-2017
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ddf439cf");
  # https://support.microsoft.com/en-us/help/2553204/description-of-the-security-update-for-office-2010-november-14-2017
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?1df91bdd");
  # https://support.microsoft.com/en-us/help/4011268/descriptionofthesecurityupdateforoffice2010november14-2017
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?5199de26");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released security updates for Microsoft Office Products.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-11882");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2017-11854");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Microsoft Office CVE-2017-11882');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/11/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/11/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/11/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:office");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2017-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

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

bulletin = "MS17-11";
kbs = make_list(
  '4011604', # Office 2007 SP3
  '4011618', # Office 2010 SP2
  '4011268', # Office 2010 SP2
  '3162047', # Office 2013 SP1
  '4011262'  # Office 2016
);

if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

get_kb_item_or_exit("SMB/Registry/Enumerated", exit_code:1);

vuln = FALSE;
port = kb_smb_transport();

######################################################################
# Office 2007, 2010, 2013, 2016
######################################################################
function perform_office_checks()
{
  local_var office_vers, office_sp, common_path, path, prod, file, kb;
  office_vers = hotfix_check_office_version();

  ####################################################################
  # Office 2007 SP3 Checks
  ####################################################################
  if (office_vers["12.0"])
  {
    office_sp = get_kb_item("SMB/Office/2007/SP");
    if (!isnull(office_sp) && office_sp == 3)
    {
      prod = "Microsoft Office 2007 SP3";
      common_path = hotfix_get_officecommonfilesdir(officever:"12.0");

      path = hotfix_append_path(
               path  : common_path,
               value : "Microsoft Shared\Equation"
      );
      if (hotfix_check_fversion(file:"eqnedt32.exe", version:"2017.8.14.0", path:path, kb:"4011604", bulletin:bulletin, product:prod) == HCF_OLDER)
        vuln = TRUE;
    }
  }

  ####################################################################
  # Office 2010 SP2 Checks
  ####################################################################
  if (office_vers["14.0"])
  {
    office_sp = get_kb_item("SMB/Office/2010/SP");
    if (!isnull(office_sp) && office_sp == 2)
    {
      prod = "Microsoft Office 2010 SP2";
      common_path = hotfix_get_officecommonfilesdir(officever:"14.0");

      path = hotfix_append_path(
        path  : common_path,
        value : "Microsoft Shared\Equation"
      );
      if (hotfix_check_fversion(file:"eqnedt32.exe", version:"2017.8.14.0", path:path, kb:"4011618", bulletin:bulletin, product:prod) == HCF_OLDER)
        vuln = TRUE;

      path = hotfix_append_path(
        path  : common_path,
        value : "Microsoft Shared\Office14"
      );
      if (hotfix_check_fversion(file:"wwlibcxm.dll", version:"14.0.7190.5000", path:path, kb:"4011268", bulletin:bulletin, product:prod) == HCF_OLDER)
        vuln = TRUE;
    }
  }

  ####################################################################
  # Office 2013 SP1 Checks
  ####################################################################
  if (office_vers["15.0"])
  {
    office_sp = get_kb_item("SMB/Office/2013/SP");
    if (!isnull(office_sp) && office_sp == 1)
    {
      prod = "Microsoft Office 2013 SP1";
      common_path = hotfix_get_officecommonfilesdir(officever:"15.0");

      path = hotfix_append_path(
        path  : common_path,
        value : "Microsoft Shared\Equation"
      );
      if (hotfix_check_fversion(file:"eqnedt32.exe", version:"2017.8.14.0", path:path, kb:"3162047", bulletin:bulletin, product:prod) == HCF_OLDER)
        vuln = TRUE;
    }
  }

  ####################################################################
  # Office 2016 Checks
  ####################################################################
  if (office_vers["16.0"])
  {
    office_sp = get_kb_item("SMB/Office/2016/SP");
    if (!isnull(office_sp) && office_sp == 0)
    {
      prod = "Microsoft Office 2016";
      common_path = hotfix_get_officecommonfilesdir(officever:"16.0");

      path = hotfix_append_path(
        path  : common_path,
        value : "Microsoft Shared\Equation"
      );
      kb   = "4011262";
      file = "eqnedt32.exe";
      if (
        hotfix_check_fversion(file:file, version:"2017.8.14.0", channel:"MSI", channel_product:"Office", path:path, kb:kb, bulletin:bulletin, product:prod) == HCF_OLDER ||
        hotfix_check_fversion(file:file, version:"2017.8.14.0", channel:"Deferred", channel_product:"Office", path:path, kb:kb, bulletin:bulletin, product:prod) == HCF_OLDER ||
        hotfix_check_fversion(file:file, version:"2017.8.14.0", channel:"Deferred", channel_version:"1705", channel_product:"Office", path:path, kb:kb, bulletin:bulletin, product:prod) == HCF_OLDER ||
        hotfix_check_fversion(file:file, version:"2017.8.14.0", channel:"First Release for Deferred", channel_product:"Office", path:path, kb:kb, bulletin:bulletin, product:prod) == HCF_OLDER ||
        hotfix_check_fversion(file:file, version:"2017.8.14.0", channel:"Current", channel_product:"Office", path:path, kb:kb, bulletin:bulletin, product:prod) == HCF_OLDER
      )
        vuln = TRUE;
    }
  }
}

######################################################################
# MAIN
######################################################################
perform_office_checks();

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
