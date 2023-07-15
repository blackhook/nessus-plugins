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
  script_id(105728);
  script_version("1.13");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/25");

  script_cve_id(
    "CVE-2018-0793",
    "CVE-2018-0794",
    "CVE-2018-0795",
    "CVE-2018-0797",
    "CVE-2018-0798",
    "CVE-2018-0801",
    "CVE-2018-0802",
    "CVE-2018-0804",
    "CVE-2018-0805",
    "CVE-2018-0806",
    "CVE-2018-0807",
    "CVE-2018-0812",
    "CVE-2018-0845",
    "CVE-2018-0848",
    "CVE-2018-0849",
    "CVE-2018-0862"
  );
  script_bugtraq_id(
    102347,
    102348,
    102356,
    102370,
    102373,
    102375,
    102406,
    102457,
    102459,
    102460,
    102461,
    102463
  );
  script_xref(name:"MSKB", value:"4011201");
  script_xref(name:"MSKB", value:"4011574");
  script_xref(name:"MSKB", value:"4011580");
  script_xref(name:"MSKB", value:"4011610");
  script_xref(name:"MSKB", value:"4011611");
  script_xref(name:"MSKB", value:"4011622");
  script_xref(name:"MSKB", value:"4011632");
  script_xref(name:"MSKB", value:"4011636");
  script_xref(name:"MSKB", value:"4011656");
  script_xref(name:"MSKB", value:"4011658");
  script_xref(name:"MSFT", value:"MS17-4011201");
  script_xref(name:"MSFT", value:"MS17-4011574");
  script_xref(name:"MSFT", value:"MS17-4011580");
  script_xref(name:"MSFT", value:"MS17-4011610");
  script_xref(name:"MSFT", value:"MS17-4011611");
  script_xref(name:"MSFT", value:"MS17-4011622");
  script_xref(name:"MSFT", value:"MS17-4011632");
  script_xref(name:"MSFT", value:"MS17-4011636");
  script_xref(name:"MSFT", value:"MS17-4011656");
  script_xref(name:"MSFT", value:"MS17-4011658");
  script_xref(name:"IAVA", value:"2018-A-0009-S");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/05/03");

  script_name(english:"Security Updates for Microsoft Office Products (January 2018)");

  script_set_attribute(attribute:"synopsis", value:
"The Microsoft Office Products are missing a security update.");
  script_set_attribute(attribute:"description", value:
"The Microsoft Office Products are missing security updates.
It is, therefore, affected by the following vulnerabilities :

  - A remote code execution vulnerability exists in
    Microsoft Office software when the software fails to
    properly handle objects in memory. An attacker who
    successfully exploited the vulnerability could run
    arbitrary code in the context of the current user. If
    the current user is logged on with administrative user
    rights, an attacker could take control of the affected
    system. An attacker could then install programs; view,
    change, or delete data; or create new accounts with full
    user rights.  (CVE-2018-0794, CVE-2018-0795)

  - An Office RTF remote code execution vulnerability exists
    in Microsoft Office software when the Office software
    fails to properly handle RTF files. An attacker who
    successfully exploited the vulnerability could run
    arbitrary code in the context of the current user. If
    the current user is logged on with administrative user
    rights, an attacker could take control of the affected
    system. An attacker could then install programs; view,
    change, or delete data; or create new accounts with full
    user rights.  (CVE-2018-0797)

  - A remote code execution vulnerability exists in
    Microsoft Office software when the software fails to
    properly handle objects in memory. An attacker who
    successfully exploited the vulnerability could run
    arbitrary code in the context of the current user. If
    the current user is logged on with administrative user
    rights, an attacker could take control of the affected
    system. An attacker could then install programs; view,
    change, or delete data; or create new accounts with full
    user rights.  (CVE-2018-0798, CVE-2018-0801,
    CVE-2018-0802, CVE-2018-0804, CVE-2018-0805,
    CVE-2018-0806, CVE-2018-0807, CVE-2018-0812)

  - A remote code execution vulnerability exists in the way
    that Microsoft Outlook parses specially crafted email
    messages. An attacker who successfully exploited the
    vulnerability could take control of an affected system.
    An attacker could then install programs; view, change,
    or delete data; or create new accounts with full user
    rights. Exploitation of this vulnerability requires that
    a user open a specially crafted file with an affected
    version of Microsoft Outlook.  (CVE-2018-0793)");
  # https://support.microsoft.com/en-ie/help/4011201/descriptionofthesecurityupdateforoffice2007january92018
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e1b2b6d9");
  # https://support.microsoft.com/en-us/help/4011574/descriptionofthesecurityupdateforoffice2016january9-2018
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?85b6869a");
  # https://support.microsoft.com/en-us/help/4011580/descriptionofthesecurityupdateforoffice2013january9-2018
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?7d51c8cf");
  # https://support.microsoft.com/en-us/help/4011610/descriptionofthesecurityupdateforoffice2010january9-2018
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e7a15426");
  # https://support.microsoft.com/en-ie/help/4011611/descriptionofthesecurityupdateforoffice2010january9-2018
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?00956959");
  # https://support.microsoft.com/en-ie/help/4011622/descriptionofthesecurityupdateforoffice2016january9-2018
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?40ab628d");
  # https://support.microsoft.com/en-us/help/4011632/descriptionofthesecurityupdateforoffice2016january9-2018
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?7cb9348d");
  # https://support.microsoft.com/en-ie/help/4011636/descriptionofthesecurityupdateforoffice2013january9-2018
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?479ec626");
  # https://support.microsoft.com/en-us/help/4011656/descriptionofthesecurityupdatefor2007microsoftofficesuitejanuary9-2018
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?cf086d09");
  # https://support.microsoft.com/en-us/help/4011658/descriptionofthesecurityupdateforoffice2010january9-2018
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?2b10eed9");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released the following security updates to address this issue:
  -KB4011201
  -KB4011574
  -KB4011580
  -KB4011610
  -KB4011611
  -KB4011622
  -KB4011632
  -KB4011636
  -KB4011656
  -KB4011658");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-0862");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/01/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/01/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/01/10");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:office");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2018-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

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

bulletin = "MS18-01";
kbs = make_list(
  '4011201', # Office 2007 SP3
  '4011574', # Office 2016
  '4011580', # Office 2013 SP1
  '4011610', # Office 2010 SP2
  '4011611', # Office 2010 SP2
  '4011622', # Office 2016
  '4011632', # Office 2016
  '4011636', # Office 2013 SP1
  '4011656', # Office 2007 SP3
  '4011658'  # Office 2010 SP2
);

if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

get_kb_item_or_exit("SMB/Registry/Enumerated", exit_code:1);

vuln = FALSE;
port = kb_smb_transport();

######################################################################
# Office 2007, 2010, 2013, 2016
# note that this batch of updates deletes eqnedt32.exe
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
      if (hotfix_check_fversion(file:"mso.dll", version:"12.0.6784.5000", path:path, kb:"4011201", bulletin:bulletin, product:prod) == HCF_OLDER)
        vuln = TRUE;

      path = hotfix_append_path(
        path  : common_path,
        value : "Microsoft Shared\Equation"
      );
# note that this update deletes eqnedt32.exe
      if (hotfix_check_fversion(file:"eqnedt32.exe", version:"2018.0.0.0", path:path, kb:"4011656", bulletin:bulletin, product:prod) == HCF_OLDER)
        vuln = TRUE;
    }
  }

  ####################################################################
  # Office 2010 SP2 Checks
  # wwlibcxm.dll only exists if KB2428677 is installed
  ####################################################################
  if (office_vers["14.0"])
  {
    office_sp = get_kb_item("SMB/Office/2010/SP");
    if (!isnull(office_sp) && office_sp == 2)
    {
      prod = "Microsoft Office 2010 SP2";

      path = hotfix_get_officeprogramfilesdir(officever:"14.0");
      if (hotfix_check_fversion(file:"wwlibcxm.dll", version:"14.0.7192.5000", path:path, kb:"4011658", bulletin:bulletin, product:prod) == HCF_OLDER)
        vuln = TRUE;

      common_path = hotfix_get_officecommonfilesdir(officever:"14.0");
      path = hotfix_append_path(
        path  : common_path,
        value : "Microsoft Shared\Office14"
      );
      if (hotfix_check_fversion(file:"mso.dll", version:"14.0.7192.5000", path:path, kb:"4011611", bulletin:bulletin, product:prod) == HCF_OLDER)
        vuln = TRUE;

      path = hotfix_append_path(
        path  : common_path,
        value : "Microsoft Shared\Equation"
      );
# note that this update deletes eqnedt32.exe
      if (hotfix_check_fversion(file:"eqnedt32.exe", version:"2018.0.0.0", path:path, kb:"4011610", bulletin:bulletin, product:prod) == HCF_OLDER)
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
      if (hotfix_check_fversion(file:"mso.dll", version:"15.0.4997.1000", path:path, kb:"4011636", bulletin:bulletin, product:prod) == HCF_OLDER)
        vuln = TRUE;

      path = hotfix_append_path(
        path  : common_path,
        value : "Microsoft Shared\Equation"
      );
# note that this update deletes eqnedt32.exe
      if (hotfix_check_fversion(file:"eqnedt32.exe", version:"2018.0.0.0", path:path, kb:"4011580", bulletin:bulletin, product:prod) == HCF_OLDER)
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
      kb = "4011632";
      if (
        hotfix_check_fversion(file:file, version:"16.0.4639.1000", channel:"MSI", channel_product:"Office", path:path, kb:kb, bulletin:bulletin, product:prod) == HCF_OLDER ||
        hotfix_check_fversion(file:file, version:"16.0.8201.2217", channel:"Deferred", channel_product:"Office", path:path, kb:kb, bulletin:bulletin, product:prod) == HCF_OLDER ||
        hotfix_check_fversion(file:file, version:"16.0.8431.2153", channel:"Deferred", channel_version:"1708", channel_product:"Office", path:path, kb:kb, bulletin:bulletin, product:prod) == HCF_OLDER ||
        hotfix_check_fversion(file:file, version:"16.0.8431.2153", channel:"First Release for Deferred", channel_product:"Office", path:path, kb:kb, bulletin:bulletin, product:prod) == HCF_OLDER ||
        hotfix_check_fversion(file:file, version:"16.0.8730.2175", channel:"Current", channel_product:"Office", path:path, kb:kb, bulletin:bulletin, product:prod) == HCF_OLDER
        )
        vuln = TRUE;

      file = "mso99lres.dll";
      c2r_file = "mso.dll";
      kb = "4011622";
      if (
        hotfix_check_fversion(file:file, version:"16.0.4519.1000", channel:"MSI", channel_product:"Office", path:path, kb:kb, bulletin:bulletin, product:prod) == HCF_OLDER ||
        hotfix_check_fversion(file:c2r_file, version:"16.0.8201.2217", channel:"Deferred", channel_product:"Office", path:path, kb:kb, bulletin:bulletin, product:prod) == HCF_OLDER ||
        hotfix_check_fversion(file:c2r_file, version:"16.0.8431.2153", channel:"Deferred", channel_version:"1708", channel_product:"Office", path:path, kb:kb, bulletin:bulletin, product:prod) == HCF_OLDER ||
        hotfix_check_fversion(file:c2r_file, version:"16.0.8431.2153", channel:"First Release for Deferred", channel_product:"Office", path:path, kb:kb, bulletin:bulletin, product:prod) == HCF_OLDER ||
        hotfix_check_fversion(file:c2r_file, version:"16.0.8730.2175", channel:"Current", channel_product:"Office", path:path, kb:kb, bulletin:bulletin, product:prod) == HCF_OLDER
        )
        vuln = TRUE;

      path = hotfix_append_path(
        path  : common_path,
        value : "Microsoft Shared\EQUATION"
      );
      file = "eqnedt32.exe";
      kb = "4011574";
# note that this update deletes eqnedt32.exe
      if (
        hotfix_check_fversion(file:file, version:"2018.0.0.0", channel:"MSI", channel_product:"Office", path:path, kb:kb, bulletin:bulletin, product:prod) == HCF_OLDER ||
        hotfix_check_fversion(file:file, version:"2018.0.0.0", channel:"Deferred", channel_product:"Office", path:path, kb:kb, bulletin:bulletin, product:prod) == HCF_OLDER ||
        hotfix_check_fversion(file:file, version:"2018.0.0.0", channel:"Deferred", channel_version:"1708", channel_product:"Office", path:path, kb:kb, bulletin:bulletin, product:prod) == HCF_OLDER ||
        hotfix_check_fversion(file:file, version:"2018.0.0.0", channel:"First Release for Deferred", channel_product:"Office", path:path, kb:kb, bulletin:bulletin, product:prod) == HCF_OLDER ||
        hotfix_check_fversion(file:file, version:"2018.0.0.0", channel:"Current", channel_product:"Office", path:path, kb:kb, bulletin:bulletin, product:prod) == HCF_OLDER
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
