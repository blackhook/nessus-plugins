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
  script_id(105698);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/06/03");

  script_cve_id("CVE-2018-0792", "CVE-2018-0797");
  script_bugtraq_id(102381, 102406);
  script_xref(name:"MSKB", value:"4011021");
  script_xref(name:"MSKB", value:"4011615");
  script_xref(name:"MSKB", value:"4011648");
  script_xref(name:"MSFT", value:"MS18-4011021");
  script_xref(name:"MSFT", value:"MS18-4011615");
  script_xref(name:"MSFT", value:"MS18-4011648");
  script_xref(name:"IAVA", value:"2018-A-0009-S");

  script_name(english:"Security Updates for Microsoft Office Online Server and Microsoft Office Web Apps (January 2018)");
  script_summary(english:"Checks for Microsoft security updates.");

  script_set_attribute(attribute:"synopsis", value:
"The Microsoft Office Online Server or Microsoft Office Web Apps 
installation on the remote host is affected by multiple 
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The Microsoft Office Online Server or Microsoft Office Web
Apps installation on the remote host is missing security
updates. It is, therefore, affected by multiple
vulnerabilities :

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
    user rights.  (CVE-2018-0792)");
  # https://support.microsoft.com/en-us/help/4011021/descriptionofthesecurityupdateforofficeonlineserverjanuary9
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?16397184");
  # https://support.microsoft.com/en-us/help/4011615/descriptionofthesecurityupdateforsharepointserver2010officewebappsjanu
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?9c67cb23");
  # https://support.microsoft.com/en-us/help/4011648/descriptionofthesecurityupdateforofficewebappsserver2013january9-2018
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?3bd3dba0");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released the following security updates to address this issue:  
  -KB4011021
  -KB4011615
  -KB4011648");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-0797");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/01/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/01/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/01/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:office_online_server");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:office_web_apps");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2018-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

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

bulletin = "MS18-01";
kbs = make_list(
  "4011648",
  "4011615",
  "4011021"
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

function perform_owa_checks()
{
  local_var owa_installs, owa_install;
  local_var owa_2010_path, owa_2010_sp;
  local_var owa_2013_path, owa_2013_sp;
  local_var path;
  local_var vuln;

  # Get installs of Office Web Apps
  owa_installs = get_installs(app_name:"Microsoft Office Web Apps");

  if (!empty_or_null(owa_installs))
  {
    foreach owa_install (owa_installs[1])
    {
       if (owa_install["Product"] == "2010")
       {
         owa_2010_path = owa_install['path'];
         owa_2010_sp = owa_install['SP'];
       } else if (owa_install["Product"] == "2013")
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
    path = hotfix_append_path(path:owa_2010_path, value:"14.0\WebServices\WordServer\Core");
    if (hotfix_check_fversion(file:"sword.dll", version:"14.0.7192.5000", min_version:"14.0.0.0", path:path, kb:"4011615", product:"Office Web Apps 2010") == HCF_OLDER)
      vuln = TRUE;
  }



  ####################################################################
  # Office Web Apps 2013 SP1
  ####################################################################
  if (owa_2013_path && (!isnull(owa_2013_sp) && owa_2013_sp == "1"))
  {
    path = hotfix_append_path(path:owa_2013_path, value:"WordConversionService\bin\Converter");
    if (hotfix_check_fversion(file:"sword.dll", version:"15.0.4997.1000", min_version:"15.0.0.0", path:path, kb:"4011648", product:"Office Web Apps 2013") == HCF_OLDER)
      vuln = TRUE;
  }
  return vuln;
}


######################################################################
# Office Online Server
######################################################################
function perform_oos_checks()
{
  local_var vuln, path;
  if(office_online_server_path)
  {
    path = hotfix_append_path(path:office_online_server_path, value:"WordConversionService\bin\Converter");
    if (hotfix_check_fversion(file:"sword.dll", version:"16.0.8431.1021", min_version:"16.0.6000.0", path:path, kb:"4011021", product:"Office Online Server") == HCF_OLDER)

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
