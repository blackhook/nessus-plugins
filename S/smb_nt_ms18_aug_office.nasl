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
  script_id(111696);
  script_version("1.7");
  script_cvs_date("Date: 2019/11/04");

  script_cve_id("CVE-2018-8378");
  script_xref(name:"MSKB", value:"4022198");
  script_xref(name:"MSKB", value:"3213636");
  script_xref(name:"MSKB", value:"4032239");
  script_xref(name:"MSKB", value:"4032233");
  script_xref(name:"MSFT", value:"MS18-4022198");
  script_xref(name:"MSFT", value:"MS18-3213636");
  script_xref(name:"MSFT", value:"MS18-4032239");
  script_xref(name:"MSFT", value:"MS18-4032233");

  script_name(english:"Security Updates for Microsoft Office Products (August 2018)");
  script_summary(english:"Checks for Microsoft security updates.");

  script_set_attribute(attribute:"synopsis", value:
"The Microsoft Office Products are missing a security update.");
  script_set_attribute(attribute:"description", value:
"The Microsoft Office Products are missing a security update.
It is, therefore, affected by the following vulnerability :

  - An information disclosure vulnerability exists when
    Microsoft Office software reads out of bound memory due
    to an uninitialized variable, which could disclose the
    contents of memory. An attacker who successfully
    exploited the vulnerability could view out of bound
    memory. Exploitation of the vulnerability requires that
    a user open a specially crafted file with an affected
    version of Microsoft Office software. The security
    update addresses the vulnerability by properly
    initializing the affected variable. (CVE-2018-8378)");
  # https://support.microsoft.com/en-us/help/4022198/description-of-the-security-update-for-office-2010-august-14-2018
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?3ef5803a");
  # https://support.microsoft.com/en-us/help/3213636/description-of-the-security-update-for-office-2010-august-14-2018
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?93f05eca");
  # https://support.microsoft.com/en-us/help/4032239/description-of-the-security-update-for-office-2013-august-14-2018
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?374c2453");
  # https://support.microsoft.com/en-us/help/4032233/description-of-the-security-update-for-office-2016-august-14-2018
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?defec16d");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released the following security updates to address this issue:  
  -KB4022198
  -KB3213636
  -KB4032239
  -KB4032233");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-8378");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/08/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/08/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/08/14");

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

bulletin = "MS18-08";
kbs = make_list(
  '3213636', # Office 2010 SP2
  '4022198', # Office 2010 SP2
  '4032239', # Office 2013 SP1
  '4032233'  # Office 2016
);

if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_WARNING);

get_kb_item_or_exit("SMB/Registry/Enumerated", exit_code:1);

vuln = FALSE;
port = kb_smb_transport();

######################################################################
# Office 2010, 2013, 2016
######################################################################
function perform_office_checks()
{
  local_var office_vers, office_sp, common_path, path, prod, file, kb, c2r_file, infopath_prod, msi_path, c2r_path, checks;
  office_vers = hotfix_check_office_version();

  ####################################################################
  # Office 2010 SP2 Checks
  ####################################################################
  if (office_vers["14.0"])
  {
    office_sp = get_kb_item("SMB/Office/2010/SP");
    if (!isnull(office_sp) && office_sp == 2)
    {
      prod = "Microsoft Office 2010 SP2";

      path = hotfix_get_officeprogramfilesdir(officever:"14.0");
      path = hotfix_append_path(
        path  : path,
        value : "Microsoft Office\Office14"
      );

      if (hotfix_check_fversion(file:"offowc.dll", version:"14.0.7212.5000", path:path, kb:"3213636", bulletin:bulletin, product:prod) == HCF_OLDER)
        vuln = TRUE;

      path = hotfix_get_officecommonfilesdir(officever:"14.0");
      path = hotfix_append_path(
        path  : path,
        value : "Microsoft Shared\Office14"
      );

      if (hotfix_check_fversion(file:"mso.dll", version:"14.0.7212.5000", path:path, kb:"4022198", bulletin:bulletin, product:prod) == HCF_OLDER)
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

      path = hotfix_get_officecommonfilesdir(officever:"15.0");
      path = hotfix_append_path(
        path  : path,
        value : "Microsoft Shared\Office15"
      );

      if (hotfix_check_fversion(file:"mso.dll", version:"15.0.5059.1000", path:path, kb:"4032239", bulletin:bulletin, product:prod) == HCF_OLDER)
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

      path = hotfix_get_officecommonfilesdir(officever:"16.0");
      msi_path = hotfix_append_path(path: path, value : "Microsoft Shared\Office16");
      c2r_path = msi_path;
      file = "mso.dll";
      kb = "4032233";
      if (
        hotfix_check_fversion(file:file, version:"16.0.4732.1000", channel:"MSI", channel_product:"Office", path:msi_path, kb:kb, bulletin:bulletin, product:prod) == HCF_OLDER ||
        hotfix_check_fversion(file:file, version:"16.0.8431.2299", channel:"Deferred", channel_product:"Office", path:c2r_path, kb:kb, bulletin:bulletin, product:prod) == HCF_OLDER ||
        hotfix_check_fversion(file:file, version:"16.0.9126.2275", channel:"Deferred", channel_version:"1803", channel_product:"Office", path:c2r_path, kb:kb, bulletin:bulletin, product:prod) == HCF_OLDER ||
        hotfix_check_fversion(file:file, version:"16.0.9126.2275", channel:"First Release for Deferred", channel_product:"Office", path:c2r_path, kb:kb, bulletin:bulletin, product:prod) == HCF_OLDER ||
        hotfix_check_fversion(file:file, version:"16.0.10325.20118", channel:"Current", channel_product:"Office", path:c2r_path, kb:kb, bulletin:bulletin, product:prod) == HCF_OLDER
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
  hotfix_security_warning();
  hotfix_check_fversion_end();
  exit(0);
}
else
{
  hotfix_check_fversion_end();
  audit(AUDIT_HOST_NOT, 'affected');
}
