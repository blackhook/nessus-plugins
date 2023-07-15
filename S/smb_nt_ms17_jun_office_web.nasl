#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(100783);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/02/17");

  script_cve_id("CVE-2017-8509", "CVE-2017-8511", "CVE-2017-8512");
  script_bugtraq_id(98812, 98815, 98816);
  script_xref(name:"MSKB", value:"3203391");
  script_xref(name:"MSKB", value:"3203466");
  script_xref(name:"MSKB", value:"3203485");
  script_xref(name:"MSFT", value:"MS17-3203391");
  script_xref(name:"MSFT", value:"MS17-3203466");
  script_xref(name:"MSFT", value:"MS17-3203485");
  script_xref(name:"IAVA", value:"2017-A-0179-S");

  script_name(english:"Security Update for Microsoft Office Web Apps Server / Office Online Server (June 2017)");

  script_set_attribute(attribute:"synopsis", value:
"An application installed on the remote Windows host is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The Microsoft Office Online Server or Office Web Apps Server installed
on the remote Windows host is missing a security update. It is,
therefore, affected by multiple remote code execution vulnerabilities
in Microsoft Office software due to improper handling of objects in
memory. An unauthenticated, remote attacker can exploit these
vulnerabilities, by convincing a user to open a specially crafted
Office document, to execute arbitrary code in the context of the
current user.");
  # https://support.microsoft.com/en-us/help/3203391/descriptionofthesecurityupdateforofficewebappsserver2013june13-2017
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?3f96770a");
  # https://support.microsoft.com/en-us/help/3203466/descriptionofthesecurityupdateforsharepointserver2010officewebappsjune
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?cc85377d");
  # https://support.microsoft.com/en-us/help/3203485/description-of-the-security-update-for-office-online-server-june-13-20
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?9d99be37");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Microsoft Office Web Apps
Server 2013 and Office Online Server.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/06/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/06/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/06/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:office_web_apps");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:office_online_server");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2017-2023 Tenable Network Security, Inc.");

  script_dependencies("office_installed.nasl", "microsoft_owa_installed.nbin", "microsoft_office_compatibility_pack_installed.nbin", "smb_hotfixes.nasl", "ms_bulletin_checks_possible.nasl");
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

bulletin = "MS17-06";
kbs = make_list(
  "3203391",
  "3203466",
  "3203485"
);

if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

get_kb_item_or_exit("SMB/Registry/Enumerated", exit_code:1);

registry_init();
hklm = registry_hive_connect(hive:HKEY_LOCAL_MACHINE, exit_on_fail:TRUE);
global_var office_online_server_path = get_registry_value(
  handle : hklm,
  item   : "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Office16.WacServer\InstallLocation"
);
RegCloseKey(handle:hklm);
close_registry(close:FALSE);

port = kb_smb_transport();

######################################################################
# Office Web Apps 2010, 2013
######################################################################
function perform_owa_checks()
{
  var owa_installs, owa_install;
  var owa_2010_path, owa_2010_sp;
  var owa_2013_path, owa_2013_sp;
  var path;
  var vuln;

  # Get installs of Office Web Apps
  owa_installs = get_installs(app_name:"Microsoft Office Web Apps");
  if (!empty_or_null(owa_installs))
  {
    foreach owa_install (owa_installs[1])
    {
      if (owa_install["Product"] == "2010")
      {
        owa_2010_path = owa_install["path"];
        owa_2010_sp = owa_install["SP"];
      }
      else if (owa_install["Product"] == "2013")
      {
        owa_2013_path = owa_install["path"];
        owa_2013_sp = owa_install["SP"];
      }
    }
  }

  ####################################################################
  # Office Web Apps 2010 SP2
  ####################################################################
  if (owa_2010_path && (!isnull(owa_2010_sp) && owa_2010_sp == "2"))
  {
    path = hotfix_append_path(path:owa_2010_path, value:"14.0\WebServices\ConversionService\Bin\Converter");
    if (hotfix_check_fversion(file:"sword.dll", version:"14.0.7182.5000", min_version:"14.0.7015.1000", path:path, kb:"3203466", product:"Office Web Apps 2010") == HCF_OLDER)
      vuln = TRUE;
  }

  ####################################################################
  # Office Web Apps 2013 SP1
  ####################################################################
  if (owa_2013_path && (!isnull(owa_2013_sp) && owa_2013_sp == "1"))
  {
    path = hotfix_append_path(path:owa_2013_path, value:"WordConversionService\bin\Converter");
    if (hotfix_check_fversion(file:"sword.dll", version:"15.0.4937.1000", min_version:"15.0.4571.1500", path:path, kb:"3203391", product:"Office Web Apps 2013") == HCF_OLDER)
      vuln = TRUE;
  }
  return vuln;
}

######################################################################
# Office Online Server
######################################################################
function perform_oos_checks()
{
  var vuln, path;

  if(office_online_server_path)
  {
    path = hotfix_append_path(path:office_online_server_path, value:"WordConversionService\bin\Converter");
    if (hotfix_check_fversion(file:"sword.dll", version:"16.0.7726.1043", min_version:"16.0.6000.0", path:path, kb:"3203485", product:"Office Online Server") == HCF_OLDER)
      vuln = TRUE;
  }
  return vuln;
}

global_var vuln = 0;
vuln += perform_owa_checks();
vuln += perform_oos_checks();

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
