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
  script_id(103192);
  script_version("1.9");
  script_cvs_date("Date: 2019/11/12");

  script_cve_id(
    "CVE-2017-8631",
    "CVE-2017-8696",
    "CVE-2017-8742",
    "CVE-2017-8743"
  );
  script_bugtraq_id(
    100741,
    100746,
    100751,
    100780
  );
  script_xref(name:"MSKB", value:"3213562");
  script_xref(name:"MSFT", value:"MS17-3213562");
  script_xref(name:"MSKB", value:"3213632");
  script_xref(name:"MSFT", value:"MS17-3213632");
  script_xref(name:"MSKB", value:"3213658");
  script_xref(name:"MSFT", value:"MS17-3213658");
  script_xref(name:"IAVA", value:"2017-A-0274");

  script_name(english:"Security Update for Microsoft Office Online Server and Office Web Apps (September 2017)");
  script_summary(english:"Checks the file versions.");

  script_set_attribute(attribute:"synopsis", value:
"An application installed on the remote Windows host is affected by
multiple remote code execution vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The Microsoft Office Online Server or Microsoft Office Web
Apps installation on the remote host is missing security
updates. It is, therefore, affected by multiple
vulnerabilities :

  - A remote code execution vulnerability exists in
    Microsoft Office software when it fails to properly
    handle objects in memory. An attacker who successfully
    exploited the vulnerability could use a specially
    crafted file to perform actions in the security context
    of the current user. For example, the file could then
    take actions on behalf of the logged-on user with the
    same permissions as the current user. Exploitation of
    this vulnerability requires that a user open a specially
    crafted file with an affected version of Microsoft
    Office software. In an email attack scenario, an
    attacker could exploit the vulnerability by sending the
    specially crafted file to the user and convincing the
    user to open the file. In a web-based attack scenario,
    an attacker could host a website (or leverage a
    compromised website that accepts or hosts user-provided
    content) that contains a specially crafted file that is
    designed to exploit the vulnerability. However, an
    attacker would have no way to force the user to visit
    the website. Instead, an attacker would have to convince
    the user to click a link, typically by way of an
    enticement in an email or Instant Messenger message, and
    then convince the user to open the specially crafted
    file. The security update addresses the vulnerability by
    correcting how Microsoft Office handles files in memory.
    (CVE-2017-8631)

  - A remote code execution vulnerability exists in
    Microsoft Office software when the software fails to
    properly handle objects in memory. An attacker who
    successfully exploited the vulnerability could run
    arbitrary code in the context of the current user. If
    the current user is logged on with administrative user
    rights, an attacker could take control of the affected
    system. An attacker could then install programs; view,
    change, or delete data; or create new accounts with full
    user rights. Users whose accounts are configured to have
    fewer user rights on the system could be less impacted
    than users who operate with administrative user rights.
    Exploitation of the vulnerability requires that a user
    open a specially crafted file with an affected version
    of Microsoft Office software. In an email attack
    scenario, an attacker could exploit the vulnerability by
    sending the specially crafted file to the user and
    convincing the user to open the file. In a web-based
    attack scenario, an attacker could host a website (or
    leverage a compromised website that accepts or hosts
    user-provided content) that contains a specially crafted
    file designed to exploit the vulnerability. An attacker
    would have no way to force users to visit the website.
    Instead, an attacker would have to convince users to
    click a link, typically by way of an enticement in an
    email or instant message, and then convince them to open
    the specially crafted file. Note that the Preview Pane
    is not an attack vector for this vulnerability. The
    security update addresses the vulnerability by
    correcting how Office handles objects in memory.
    (CVE-2017-8742, CVE-2017-8743)

  - A remote code execution vulnerability exists due to the
    way Windows Uniscribe handles objects in memory. An
    attacker who successfully exploited this vulnerability
    could take control of the affected system. An attacker
    could then install programs; view, change, or delete
    data; or create new accounts with full user rights.
    Users whose accounts are configured to have fewer user
    rights on the system could be less impacted than users
    who operate with administrative user rights. There are
    multiple ways an attacker could exploit this
    vulnerability: In a web-based attack scenario, an
    attacker could host a specially crafted website designed
    to exploit this vulnerability and then convince a user
    to view the website. An attacker would have no way to
    force users to view the attacker-controlled content.
    Instead, an attacker would have to convince users to
    take action, typically by getting them to click a link
    in an email or instant message that takes users to the
    attacker's website, or by opening an attachment sent
    through email. In a file-sharing attack scenario, an
    attacker could provide a specially crafted document file
    designed to exploit this vulnerability and then convince
    a user to open the document file.The security update
    addresses the vulnerability by correcting how Windows
    Uniscribe handles objects in memory. (CVE-2017-8696)");
  # https://support.microsoft.com/en-us/help/3213658/descriptionofthesecurityupdateforofficeonlineserverseptember12-2017
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?8f1bdca6");
  # https://support.microsoft.com/en-us/help/3213632/descriptionofthesecurityupdateforsharepointserver2010officewebappssept
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ab979819");
  # https://support.microsoft.com/en-us/help/3213562/descriptionofthesecurityupdateforofficewebappsserver2013september12-20
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?75d14528");
  script_set_attribute(attribute:"see_also", value:"https://portal.msrc.microsoft.com/en-us/security-guidance/summary");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Microsoft Office Online
Server, Office Web Apps Server 2013, Office 2010 Web Apps, and Office
2013 Web Apps.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-8743");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/09/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/09/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/09/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:office_web_apps");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:office_online_server");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2017-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

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

bulletin = "MS17-09";
kbs = make_list(
  "3213562",
  "3213632",
  "3213658"
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
    path = hotfix_append_path(path:owa_2010_path, value:"14.0\WebServices\WordServer\Core");
    if (hotfix_check_fversion(file:"msoserver.dll", version:"14.0.7188.5000", min_version:"14.0.0.0", path:path, kb:"3213632", product:"Office Web Apps 2010") == HCF_OLDER)

      vuln = TRUE;
  }

  ####################################################################
  # Office Web Apps 2013 SP1
  ####################################################################
  if (owa_2013_path && (!isnull(owa_2013_sp) && owa_2013_sp == "1"))
  {
    path = hotfix_append_path(path:owa_2013_path, value:"WordConversionService\bin\Converter");
    if (hotfix_check_fversion(file:"sword.dll", version:"15.0.4963.1000", min_version:"15.0.4569.1500", path:path, kb:"3213562", product:"Office Web Apps 2013") == HCF_OLDER)

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

  if (office_online_server_path)
  {
    path = hotfix_append_path(path:office_online_server_path, value:"WordConversionService\bin\Converter");
    if (hotfix_check_fversion(file:"sword.dll", version:"16.0.7726.1056", min_version:"16.0.6000.0", path:path, kb:"3213658", product:"Office Online Server") == HCF_OLDER)

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
