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
  script_id(135682);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/28");

  script_cve_id("CVE-2020-0931");
  script_xref(name:"MSKB", value:"2553306");
  script_xref(name:"MSFT", value:"MS20-2553306");

  script_name(english:"Security Updates for Microsoft Business Productivity Server (April 2020)");

  script_set_attribute(attribute:"synopsis", value:
"The Microsoft Business Productivity Server installation on the remote host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The Microsoft Business Productivity Server installation on
the remote host is missing a security update. It is,
therefore, affected by the following vulnerability :

  - A remote code execution vulnerability exists in
    Microsoft SharePoint when the software fails to check
    the source markup of an application package. An attacker
    who successfully exploited the vulnerability could run
    arbitrary code in the context of the SharePoint
    application pool and the SharePoint server farm account.
    Exploitation of this vulnerability requires that a user
    uploads a specially crafted SharePoint application
    package to an affected version of SharePoint. The
    security update addresses the vulnerability by
    correcting how SharePoint checks the source markup of
    application packages. (CVE-2020-0931)");
  # https://support.microsoft.com/en-us/help/2553306/security-update-for-sharepoint-server-2010-april-14
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d556e2bb");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released KB2553306 to address this issue.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-0931");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/04/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/04/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/04/16");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:sharepoint_foundation");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:sharepoint_server");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2020-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("microsoft_sharepoint_installed.nbin", "smb_hotfixes.nasl", "ms_bulletin_checks_possible.nasl");
  script_require_keys("SMB/MS_Bulletin_Checks/Possible");
  script_require_ports(139, 445, "Host/patch_management_checks");

  exit(0);
}

include('audit.inc');
include('smb_func.inc');
include('smb_hotfixes.inc');
include('smb_hotfixes_fcheck.inc');
include('smb_reg_query.inc');
include('misc_func.inc');
include('install_func.inc');

get_kb_item_or_exit('SMB/MS_Bulletin_Checks/Possible');

bulletin = 'MS20-04';
kbs = make_list(
  '2553306'  # 2010 Microsoft Business Productivity Servers 
);

if (get_kb_item("Host/patch_management_checks"))
  hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_WARNING);

get_kb_item_or_exit("SMB/Registry/Enumerated", exit_code:1);

# Get path information for Windows.
windir = hotfix_get_systemroot();
if (isnull(windir)) exit(1, "Failed to determine the location of %windir%.");

registry_init();

var sps_2010_path, sps_2010_sp, sps_2010_edition;

vuln = FALSE;
port = kb_smb_transport();

installs = get_installs(app_name:"Microsoft SharePoint Server", exit_if_not_found:TRUE);

foreach install (installs[1])
{
  if (install["Product"] == "2010")
  {
    sps_2010_path = install['path'];
    sps_2010_sp = install['SP'];
    sps_2010_edition = install['Edition'];
  }
}

######################################################################
# SharePoint Server 2010 SP2
######################################################################

if (sps_2010_path && sps_2010_sp == "2" && sps_2010_edition == "Server")
{

  commonfiles = hotfix_get_commonfilesdir();
  path = hotfix_append_path(path:commonfiles, value:"microsoft shared\Web Server Extensions\14\TEMPLATE\LAYOUTS\ppsma\1033\DesignerInstall");
  if (hotfix_check_fversion(file:"Microsoft.PerformancePoint.Scorecards.Client.dll.deploy", version:"14.0.7248.5000", min_version:"14.0.0.0", path:path, kb:"2553306", product:"SharePoint 2010 for Microsoft Business Productivity Servers") == HCF_OLDER)
    vuln = TRUE;
}

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
