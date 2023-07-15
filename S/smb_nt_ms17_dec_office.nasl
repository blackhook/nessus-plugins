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
  script_id(105189);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/02/17");

  script_cve_id("CVE-2017-11934", "CVE-2017-11935", "CVE-2017-11939");
  script_bugtraq_id(102064, 102067, 102105);
  script_xref(name:"MSKB", value:"4011612");
  script_xref(name:"MSKB", value:"4011277");
  script_xref(name:"MSKB", value:"4011095");
  script_xref(name:"MSFT", value:"MS17-4011612");
  script_xref(name:"MSFT", value:"MS17-4011277");
  script_xref(name:"MSFT", value:"MS17-4011095");
  script_xref(name:"IAVA", value:"2017-A-0363-S");

  script_name(english:"Security Updates for Microsoft Office Products (December 2017)");

  script_set_attribute(attribute:"synopsis", value:
"The Microsoft Office Products are missing a security update.");
  script_set_attribute(attribute:"description", value:
"The Microsoft Office Products are missing a security update.
It is, therefore, affected by the following vulnerability :

  - An information disclosure vulnerability exists when
    Microsoft Office improperly discloses the contents of
    its memory. An attacker who exploited the vulnerability
    could use the information to compromise the users
    computer or data.  (CVE-2017-11934)");
  # https://support.microsoft.com/en-us/help/4011612/descriptionofthesecurityupdateforoffice2010december12-2017
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d5becb1c");
  # https://support.microsoft.com/en-us/help/4011277/descriptionofthesecurityupdateforoffice2013december12-2017
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?831083d7");
  # https://support.microsoft.com/en-us/help/4011095/descriptionofthesecurityupdateforoffice2016december12-2017
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?15e91184");
  # https://docs.microsoft.com/en-us/officeupdates/monthly-channel-2017
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0fcfdea2");
  # https://docs.microsoft.com/en-us/officeupdates/semi-annual-channel-2017
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?675e9b9e");
  # https://docs.microsoft.com/en-us/officeupdates/semi-annual-channel-targeted-2017
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?48da66cc");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released the following security updates to address this issue:  
  -KB4011612
  -KB4011277
  -KB4011095");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-11935");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/12/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/12/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/12/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:office");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2017-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

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

bulletin = "MS17-12";
kbs = make_list(
  '4011612', # Office 2010 SP2
  '4011277', # Office 2013 SP1
  '4011095'  # Office 2016
);

if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

get_kb_item_or_exit("SMB/Registry/Enumerated", exit_code:1);

vuln = FALSE;
port = kb_smb_transport();

######################################################################
# Office 2010, 2013, 2016
######################################################################
function perform_office_checks()
{
  local_var office_vers, office_sp, common_path, path, prod, file, kb;
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
      if (
          hotfix_check_fversion(file:"wwlib.dll", version:"14.0.7191.5000", path:path, kb:"4011612", bulletin:bulletin, product:prod) == HCF_OLDER
         )
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

      if (
          hotfix_check_fversion(file:"igx.dll", version:"15.0.4981.1000", path:path, kb:"4011277", bulletin:bulletin, product:prod) == HCF_OLDER 
         )
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

      file="chart.dll";
      kb="4011095";

      if (
        hotfix_check_fversion(file:file, version:"16.0.4627.1000", channel:"MSI", channel_product:"Office", path:path, kb:kb, bulletin:bulletin, product:prod) == HCF_OLDER ||
        hotfix_check_fversion(file:file, version:"16.0.7726.1062", channel:"Deferred", channel_product:"Office", path:path, kb:kb, bulletin:bulletin, product:prod) == HCF_OLDER ||
        hotfix_check_fversion(file:file, version:"16.0.8201.2213", channel:"Deferred", channel_version:"1705", channel_product:"Office", path:path, kb:kb, bulletin:bulletin, product:prod) == HCF_OLDER ||
        hotfix_check_fversion(file:file, version:"16.0.8431.2131", channel:"First Release for Deferred", channel_product:"Office", path:path, kb:kb, bulletin:bulletin, product:prod) == HCF_OLDER ||
        hotfix_check_fversion(file:file, version:"16.0.8730.2127", channel:"Current", channel_product:"Office", path:path, kb:kb, bulletin:bulletin, product:prod) == HCF_OLDER
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
