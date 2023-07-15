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
  script_id(106805);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/12/11");

  script_cve_id("CVE-2018-0851", "CVE-2018-0853");
  script_xref(name:"MSKB", value:"4011715");
  script_xref(name:"MSKB", value:"4011707");
  script_xref(name:"MSKB", value:"3114874");
  script_xref(name:"MSKB", value:"4011690");
  script_xref(name:"MSKB", value:"3172459");
  script_xref(name:"MSKB", value:"4011686");
  script_xref(name:"MSKB", value:"4011143");
  script_xref(name:"MSFT", value:"MS18-4011715");
  script_xref(name:"MSFT", value:"MS18-4011707");
  script_xref(name:"MSFT", value:"MS18-3114874");
  script_xref(name:"MSFT", value:"MS18-4011690");
  script_xref(name:"MSFT", value:"MS18-3172459");
  script_xref(name:"MSFT", value:"MS18-4011686");
  script_xref(name:"MSFT", value:"MS18-4011143");
  script_xref(name:"IAVA", value:"2018-A-0051-S");

  script_name(english:"Security Updates for Microsoft Office Products (February 2018)");
  script_summary(english:"Checks for Microsoft security updates.");

  script_set_attribute(attribute:"synopsis", value:
"The Microsoft Office Products are missing a security update.");
  script_set_attribute(attribute:"description", value:
"The Microsoft Office Products are missing security updates.
It is, therefore, affected by the following vulnerabilities :

  - A remote code execution vulnerability exists in
    Microsoft Office software when the Office software fails
    to properly handle objects in memory. An attacker who
    successfully exploited the vulnerability could run
    arbitrary code in the context of the current user. If
    the current user is logged on with administrative user
    rights, an attacker could take control of the affected
    system. An attacker could then install programs; view,
    change, or delete data; or create new accounts with full
    user rights. (CVE-2018-0851)

  - An information disclosure vulnerability exists when
    Microsoft Office software reads out of bound memory due
    to an uninitialized variable, which could disclose the
    contents of memory. An attacker who successfully
    exploited the vulnerability could view out of bound
    memory. Exploitation of the vulnerability requires that
    a user open a specially crafted file with an affected
    version of Microsoft Office software. The security
    update addresses the vulnerability by properly
    initializing the affected variable. (CVE-2018-0853)");
  # https://support.microsoft.com/en-us/help/4011715/descriptionofthesecurityupdatefor2007microsoftofficesuitefebruary13-20
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d7092ec1");
  # https://support.microsoft.com/en-us/help/4011707/descriptionofthesecurityupdateforoffice2010february13-2018
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?25ea79c7");
  # https://support.microsoft.com/en-us/help/3114874/descriptionofthesecurityupdateforoffice2010february13-2018
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?7216394c");
  # https://support.microsoft.com/en-us/help/4011690/descriptionofthesecurityupdateforoffice2013february13-2018
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?eec18988");
  # https://support.microsoft.com/en-us/help/3172459/descriptionofthesecurityupdateforoffice2013february13-2018
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c68f10e8");
  # https://support.microsoft.com/en-us/help/4011686/descriptionofthesecurityupdateforoffice2016february13-2018
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?2d37ad2f");
  # https://support.microsoft.com/en-us/help/4011143/descriptionofthesecurityupdateforoffice2016february13-2018
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0bc5ff1d");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released the following security updates to address this issue:  
  -KB4011715
  -KB4011707
  -KB3114874
  -KB4011690
  -KB3172459
  -KB4011686
  -KB4011143");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-0851");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/02/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/02/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/02/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:office");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2018-2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("office_installed.nasl", "microsoft_office_compatibility_pack_installed.nbin", "smb_hotfixes.nasl", "ms_bulletin_checks_possible.nasl");
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

bulletin = "MS18-02";
kbs = make_list(
  '4011715', # Office 2007 SP3
  '4011707', # Office 2010 SP2
  '3114874', # Office 2010 SP2
  '4011690', # Office 2013 SP1
  '3172459', # Office 2013 SP1
  '4011686', # Office 2016
  '4011143'  # Office 2016
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
  local_var office_vers, office_sp, common_path, path, prod, file, kb, c2r_file;
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
        value : "Microsoft Shared\Office12"
      );
      if (hotfix_check_fversion(file:"mso.dll", version:"12.0.6785.5000", path:path, kb:"4011715", bulletin:bulletin, product:prod) == HCF_OLDER)
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
        value : "Microsoft Shared\Office14"
      );
      if (hotfix_check_fversion(file:"mso.dll", version:"14.0.7194.5000", path:path, kb:"4011707", bulletin:bulletin, product:prod) == HCF_OLDER)
        vuln = TRUE;

      if (hotfix_check_fversion(file:"acecore.dll", version:"14.0.7194.5000", path:path, kb:"3114874", bulletin:bulletin, product:prod) == HCF_OLDER)
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
        value : "Microsoft Shared\Office15"
      );
      if (hotfix_check_fversion(file:"mso.dll", version:"15.0.5007.1000", path:path, kb:"4011690", bulletin:bulletin, product:prod) == HCF_OLDER)
        vuln = TRUE;

      if (hotfix_check_fversion(file:"acecore.dll", version:"15.0.5007.1000", path:path, kb:"3172459", bulletin:bulletin, product:prod) == HCF_OLDER)
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
        value : "Microsoft Shared\OFFICE16"
      );

      file = "mso.dll";
      kb = "4011686";
      if (
        hotfix_check_fversion(file:file, version:"16.0.4654.1000", channel:"MSI", channel_product:"Office", path:path, kb:kb, bulletin:bulletin, product:prod) == HCF_OLDER ||
        hotfix_check_fversion(file:file, version:"16.0.8201.2258", channel:"Deferred", channel_product:"Office", path:path, kb:kb, bulletin:bulletin, product:prod) == HCF_OLDER ||
        hotfix_check_fversion(file:file, version:"16.0.8431.2215", channel:"Deferred", channel_version:"1708", channel_product:"Office", path:path, kb:kb, bulletin:bulletin, product:prod) == HCF_OLDER ||
        hotfix_check_fversion(file:file, version:"16.0.8431.2215", channel:"First Release for Deferred", channel_product:"Office", path:path, kb:kb, bulletin:bulletin, product:prod) == HCF_OLDER ||
        hotfix_check_fversion(file:file, version:"16.0.9001.2171", channel:"Current", channel_product:"Office", path:path, kb:kb, bulletin:bulletin, product:prod) == HCF_OLDER
        )
        vuln = TRUE;

      file = "acecore.dll";
      kb = "4011143";
      if (
        hotfix_check_fversion(file:file, version:"16.0.4654.1000", channel:"MSI", channel_product:"Office", path:path, kb:kb, bulletin:bulletin, product:prod) == HCF_OLDER ||
        hotfix_check_fversion(file:file, version:"16.0.8201.2258", channel:"Deferred", channel_product:"Office", path:path, kb:kb, bulletin:bulletin, product:prod) == HCF_OLDER ||
        hotfix_check_fversion(file:file, version:"16.0.8431.2215", channel:"Deferred", channel_version:"1708", channel_product:"Office", path:path, kb:kb, bulletin:bulletin, product:prod) == HCF_OLDER ||
        hotfix_check_fversion(file:file, version:"16.0.8431.2215", channel:"First Release for Deferred", channel_product:"Office", path:path, kb:kb, bulletin:bulletin, product:prod) == HCF_OLDER ||
        hotfix_check_fversion(file:file, version:"16.0.9001.2171", channel:"Current", channel_product:"Office", path:path, kb:kb, bulletin:bulletin, product:prod) == HCF_OLDER
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
