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
  script_id(110498);
  script_version("1.2");
  script_cvs_date("Date: 2019/11/04");

  script_cve_id("CVE-2018-8247");
  script_xref(name:"MSKB", value:"4011026");
  script_xref(name:"MSKB", value:"4022203");
  script_xref(name:"MSKB", value:"4022183");
  script_xref(name:"MSFT", value:"MS18-4011026");
  script_xref(name:"MSFT", value:"MS18-4022203");
  script_xref(name:"MSFT", value:"MS18-4022183");

  script_name(english:"Security Updates for Microsoft Office Online Server and Microsoft Office Web Apps (June 2018)");
  script_summary(english:"Checks for Microsoft security updates.");

  script_set_attribute(attribute:"synopsis", value:
"The Microsoft Office Online Server or Microsoft Office Web Apps 
installation on the remote host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The Microsoft Office Online Server or Microsoft Office Web
Apps installation on the remote host is missing a security
update. It is, therefore, affected by the following
vulnerability :

  - An elevation of privilege vulnerability exists when
    Office Web Apps Server 2013 and Office Online Server
    fail to properly handle web requests. An attacker who
    successfully exploited this vulnerability could perform
    script/content injection attacks and attempt to trick
    the user into disclosing sensitive information.
    (CVE-2018-8247)");
  # https://support.microsoft.com/en-us/help/4011026/description-of-the-security-update-for-office-online-server-june-12
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ba942b2e");
  # https://support.microsoft.com/en-us/help/4022203/description-of-the-security-update-for-sharepoint-server-2010-office
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?27d4da8d");
  # https://support.microsoft.com/en-us/help/4022183/description-of-the-security-update-for-office-web-apps-server-2013
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?8ea76bc5");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released the following security updates to address this issue:  
  -KB4011026
  -KB4022203
  -KB4022183");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-8247");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/06/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/06/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/06/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:office_online_server");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:office_web_apps");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2018-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("office_installed.nasl", "microsoft_owa_installed.nbin", "smb_hotfixes.nasl", "ms_bulletin_checks_possible.nasl");
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

bulletin = "MS18-06";
kbs = make_list(
  "4011026",
  "4022203",
  "4022183"
);

if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_WARNING);

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
    path = hotfix_append_path(path:owa_2010_path, value:"14.0\WebServices\PowerPoint\Bin\Converter");
    if (hotfix_check_fversion(file:"ppserver.dll", version:"14.0.7210.5000", min_version:"14.0.0.0", path:path, kb:"4022203", product:"Office Web Apps 2010") == HCF_OLDER)
      vuln = TRUE;
  }



  ####################################################################
  # Office Web Apps 2013 SP1
  ####################################################################
  if (owa_2013_path && (!isnull(owa_2013_sp) && owa_2013_sp == "1"))
  {
    path = hotfix_append_path(path:owa_2013_path, value:"WordConversionService\bin\Converter");
    if (hotfix_check_fversion(file:"sword.dll", version:"15.0.5041.1000", min_version:"15.0.0.0", path:path, kb:"4022183", product:"Office Web Apps 2013") == HCF_OLDER)
      vuln = TRUE;
  }
  return vuln;
}


######################################################################
# Office Online Server (2016)
######################################################################
function perform_oos_checks()
{
  local_var vuln, path;
  if(office_online_server_path)
  {
    path = hotfix_append_path(path:office_online_server_path, value:"WordConversionService\bin\Converter");
    if (hotfix_check_fversion(file:"sword.dll", version:"16.0.8431.1027", min_version:"16.0.6000.0", path:path, kb:"4011026", product:"Office Online Server") == HCF_OLDER)

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
  hotfix_security_warning();
  hotfix_check_fversion_end();
  exit(0);
}
else
{
  hotfix_check_fversion_end();
  audit(AUDIT_HOST_NOT, 'affected');
}
