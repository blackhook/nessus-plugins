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
  script_id(108972);
  script_version("1.7");
  script_cvs_date("Date: 2019/11/08");

  script_cve_id(
    "CVE-2018-0950",
    "CVE-2018-1007",
    "CVE-2018-1026",
    "CVE-2018-1028",
    "CVE-2018-1030"
  );
  script_xref(name:"MSKB", value:"4018357");
  script_xref(name:"MSKB", value:"4011628");
  script_xref(name:"MSKB", value:"4018330");
  script_xref(name:"MSKB", value:"4018319");
  script_xref(name:"MSKB", value:"4018288");
  script_xref(name:"MSKB", value:"4018328");
  script_xref(name:"MSKB", value:"4018311");
  script_xref(name:"MSFT", value:"MS18-4018357");
  script_xref(name:"MSFT", value:"MS18-4011628");
  script_xref(name:"MSFT", value:"MS18-4018330");
  script_xref(name:"MSFT", value:"MS18-4018319");
  script_xref(name:"MSFT", value:"MS18-4018288");
  script_xref(name:"MSFT", value:"MS18-4018328");
  script_xref(name:"MSFT", value:"MS18-4018311");

  script_name(english:"Security Updates for Microsoft Office Products (April 2018)");
  script_summary(english:"Checks for Microsoft security updates.");

  script_set_attribute(attribute:"synopsis", value:
"The Microsoft Office Products are affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The Microsoft Office Products are missing security updates.
It is, therefore, affected by multiple vulnerabilities :

  - An information disclosure vulnerability exists when
    Microsoft Office improperly discloses the contents of
    its memory. An attacker who exploited the vulnerability
    could use the information to compromise the users
    computer or data.  (CVE-2018-1007)

  - An information disclosure vulnerability exists when
    Office renders Rich Text Format (RTF) email messages
    containing OLE objects when a message is opened or
    previewed. This vulnerability could potentially result
    in the disclosure of sensitive information to a
    malicious site.  (CVE-2018-0950)

  - A remote code execution vulnerability exists in
    Microsoft Office software when the software fails to
    properly handle objects in memory. An attacker who
    successfully exploited the vulnerability could run
    arbitrary code in the context of the current user. If
    the current user is logged on with administrative user
    rights, an attacker could take control of the affected
    system. An attacker could then install programs; view,
    change, or delete data; or create new accounts with full
    user rights.  (CVE-2018-1026, CVE-2018-1030)

  - A remote code execution vulnerability exists when the
    Office graphics component improperly handles specially
    crafted embedded fonts. An attacker who successfully
    exploited this vulnerability could take control of the
    affected system. An attacker could then install
    programs; view, change, or delete data; or create new
    accounts with full user rights.  (CVE-2018-1028)");
  # https://support.microsoft.com/en-us/help/4018357/description-of-the-security-update-for-office-2010-april-10-2018
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?786de97b");
  # https://support.microsoft.com/en-us/help/4011628/description-of-the-security-update-for-office-2016-april-10-2018
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?3540c129");
  # https://support.microsoft.com/en-us/help/4018330/description-of-the-security-update-for-office-2013-april-10-2018
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?4c321eb8");
  # https://support.microsoft.com/en-us/help/4018319/descriptionofthesecurityupdateforoffice2016april10-2018
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?33c07dfa");
  # https://support.microsoft.com/en-us/help/4018288/description-of-the-security-update-for-office-2013-april-10-2018
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?89cc14f2");
  # https://support.microsoft.com/en-us/help/4018328/description-of-the-security-update-for-office-2016-april-10-2018
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b34b25dc");
  # https://support.microsoft.com/en-us/help/4018311/description-of-the-security-update-for-office-2010-april-10-2018
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?011d8a4a");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released the following security updates to address this issue:  
  -KB4018357
  -KB4011628
  -KB4018330
  -KB4018319
  -KB4018288
  -KB4018328
  -KB4018311");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/04/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/04/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/04/10");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:office");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2018-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

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

bulletin = "MS18-04";
kbs = make_list(
  '4018357', # Office 2010 SP2
  '4018311', # Office 2010 SP2
  '4018288', # Office 2013 SP1
  '4018330', # Office 2013 SP1
  '4011628', # Office 2016
  '4018319', # Office 2016
  '4018328'  # Office 2016
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
      if (hotfix_check_fversion(file:"wwlibcxm.dll", version:"14.0.7197.5000", path:path, kb:"4018357", bulletin:bulletin, product:prod) == HCF_OLDER)
        vuln = TRUE;

      path = hotfix_get_officecommonfilesdir(officever:"14.0");
      path = hotfix_append_path(
        path  : path,
        value : "Microsoft Shared\Office14"
      );
      if (hotfix_check_fversion(file:"mso.dll", version:"14.0.7197.5000", path:path, kb:"4018311", bulletin:bulletin, product:prod) == HCF_OLDER)
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

      path = hotfix_get_officeprogramfilesdir(officever:"15.0");
      path = hotfix_append_path(
        path  : path,
        value : "Microsoft Office\Office15"
      );
      if (hotfix_check_fversion(file:"igx.dll", version:"15.0.5015.1000", path:path, kb:"4018288", bulletin:bulletin, product:prod) == HCF_OLDER)
        vuln = TRUE;

      path = hotfix_get_officecommonfilesdir(officever:"15.0");
      path = hotfix_append_path(
        path  : path,
        value : "Microsoft Shared\Office15"
      );
      if (hotfix_check_fversion(file:"mso.dll", version:"15.0.5023.1000", path:path, kb:"4018330", bulletin:bulletin, product:prod) == HCF_OLDER)
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

      path = hotfix_get_officeprogramfilesdir(officever:"16.0");
      path = hotfix_append_path(
        path  : path,
        value : "Microsoft Office\root\Office16"
      );
      kb   = "4011628";
      file = "igx.dll";
      if (
        hotfix_check_fversion(file:file, version:"16.0.4666.1000", channel:"MSI", channel_product:"Office", path:path, kb:kb, bulletin:bulletin, product:prod) == HCF_OLDER
      )
        vuln = TRUE;

      path = hotfix_get_officeprogramfilesdir(officever:"16.0");
      path = hotfix_append_path(
        path  : path,
        value : "Microsoft Office\root\Office16"
      );
      file = "chart.dll";
      kb = "4018319";
      if (
        hotfix_check_fversion(file:file, version:"16.0.4678.1000", channel:"MSI", channel_product:"Office", path:path, kb:kb, bulletin:bulletin, product:prod) == HCF_OLDER ||
        hotfix_check_fversion(file:file, version:"16.0.8201.2272", channel:"Deferred", channel_product:"Office", path:path, kb:kb, bulletin:bulletin, product:prod) == HCF_OLDER ||
        hotfix_check_fversion(file:file, version:"16.0.8431.2242", channel:"Deferred", channel_version:"1708", channel_product:"Office", path:path, kb:kb, bulletin:bulletin, product:prod) == HCF_OLDER ||
        hotfix_check_fversion(file:file, version:"16.0.9126.2152", channel:"First Release for Deferred", channel_product:"Office", path:path, kb:kb, bulletin:bulletin, product:prod) == HCF_OLDER ||
        hotfix_check_fversion(file:file, version:"16.0.9126.2152", channel:"Current", channel_product:"Office", path:path, kb:kb, bulletin:bulletin, product:prod) == HCF_OLDER
      )
        vuln = TRUE;

      path = hotfix_get_officecommonfilesdir(officever:"16.0");
      path = hotfix_append_path(
        path  : path,
        value : "Microsoft Shared\OFFICE16"
      );
      file = "mso.dll";
      kb = "4018328";
      if (
        hotfix_check_fversion(file:file, version:"16.0.4678.1000", channel:"MSI", channel_product:"Office", path:path, kb:kb, bulletin:bulletin, product:prod) == HCF_OLDER
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
