#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(137369);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/10/15");

  script_cve_id("CVE-2020-1331");
  script_xref(name:"MSFT", value:"MS20-06");
  script_xref(name:"MSKB", value:"4566040");
  script_xref(name:"IAVA", value:"2020-A-0258");

  script_name(english:"Security Updates for Microsoft System Center Operations Manager (June 2020)");
  script_summary(english:"Checks the version of System Center Operations Manager libraries.");

  script_set_attribute(attribute:"synopsis", value:
"A web application hosted on the remote Windows system is affected by
a spoofing vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Microsoft System Center Operations Manager installed on
the remote Windows host is affected by a spoofing
vulnerability. An attacker can exploit this vulnerability by
sending a specially crafted request to an affected SCOM instance.");
  # https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/CVE-2020-1331
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?593b93f8");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for System Center Operations
Manager 2016.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-1331");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/06/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/06/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/06/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:system_center_operations_manager");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2020-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("system_center_operations_mgr_installed.nasl", "ms_bulletin_checks_possible.nasl");
  script_require_keys("SMB/MS_Bulletin_Checks/Possible", "installed_sw/System Center Operations Manager 2016 Server");
  script_require_ports(139, 445, "Host/patch_management_checks");

  exit(0);
}

include('audit.inc');
include('smb_func.inc');
include('smb_hotfixes.inc');
include('smb_hotfixes_fcheck.inc');
include('misc_func.inc');
include('install_func.inc');
include('lists.inc');
include('debug.inc');

get_kb_item_or_exit('SMB/MS_Bulletin_Checks/Possible');

if (get_kb_item('Host/patch_management_checks'))
  hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_NOTE);

bulletin = 'MS20-06';
kbs = make_list('4566040');
app = 'System Center Operations Manager 2016 Server';

# perform install lookup
install  = get_single_install(app_name:app, exit_if_unknown_ver:FALSE);
list = get_kb_list("SMB/Registry/HKLM/SOFTWARE/Microsoft/Windows/CurrentVersion/Uninstall/*/DisplayName");
webconsole_installed = FALSE;

if (!isnull(list))
{
  # Use the installer's registry settings.
  foreach name (keys(list))
  { 
    prod = list[name];
    dbg::log(src:SCRIPT_NAME, msg:"installed product [" + prod + "]");
    
    # e.g. kb
    # SMB/Registry/HKLM/SOFTWARE/Microsoft/Windows/CurrentVersion/Uninstall/{676EB643-C22A-4EEC-A8CF-13A0719056A5}/DisplayName=System Center Operations Manager 2016 Web Console
    if (prod && "System Center" >< prod && "Operations Manager" >< prod && "2016" >< prod && "Web Console" >< prod)
    {
      webconsole_installed = TRUE;
      break;
    }
 }
}

path     = install['path'];
fix      = '7.2.12282.0';
flag     = FALSE;

get_kb_item_or_exit('SMB/Registry/Enumerated', exit_code:1);
  
# Get path information for Windows.
windir = hotfix_get_systemroot();
if (isnull(windir)) exit(1, 'Failed to determine the location of %windir%.');

if (get_kb_item('installed_sw/Microsoft Monitoring Agent'))
  audit(AUDIT_HOST_NOT, 'affected');
  
  # not sure if you can have multiple versions installed on the same system, but this code assumes that you can
paths = get_kb_list('SMB/System Center Operations Manager/Install/*');
 
if (isnull(paths))
   audit(AUDIT_NOT_INST, app);
  
failed_shares = make_list();
are_we_vuln = FALSE;
connection_made = FALSE;
  
foreach path (make_list(paths))
{
  share = path[0] + '$';
  dbg::log(src:SCRIPT_NAME, msg:"checking share:[" + share + "]");
 
  if (!is_accessible_share(share:share))
  {
    failed_shares = list_uniq(make_list(failed_shares, share));
    continue;
  }
  
  path -= "Server\";
  path += "WebConsole\MonitoringView\bin";
  file = 'Microsoft.EnterpriseManagement.OperationsManager.MonitoringViews.dll';
  file_exists = hotfix_file_exists(path:path);
  dbg::log(src:SCRIPT_NAME, msg:"searching for Microsoft.EnterpriseManagement.OperationsManager.MonitoringViews.dll --> File Exists:[" + file_exists + "]");

  if (file_exists)
  { 
    # Microsoft System Center 2016 Operations Manager
    # https://docs.microsoft.com/en-us/system-center/scom/release-build-versions?view=sc-om-2016
    are_we_vuln = hotfix_check_fversion(
      file:file,
      version:fix,
      path:path,
      kb:'4566040',
      product:app
    );
  }
}


if (are_we_vuln)
{
  report = '\n';
  report += '  Product : ' + app + '\n';
  report += '  KB : 4566040\n';
  hotfix_add_report(report, kb:'4566040');
  port = kb_smb_transport();
  replace_kb_item(name:'SMB/Missing/'+bulletin, value:TRUE);
  hotfix_security_note();
  hotfix_check_fversion_end();
  exit(0);
}
else
{
  hotfix_check_fversion_end();
  audit(AUDIT_HOST_NOT, 'affected');
}

