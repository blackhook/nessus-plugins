#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(134204);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/06/09");

  script_cve_id("CVE-2015-6161");
  script_xref(name:"MSFT", value:"MS15-124");
  script_xref(name:"MSKB", value:"3125869");

  script_name(english:"MS15-124: Cumulative Security Update for Internet Explorer (CVE-2015-6161) (3125869)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has a web browser installed that is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Internet Explorer installed on the remote host is
missing Cumulative Security Update 3125869 and/or a Registry key
to prevent the host against CVE-2015-6161. It is, therefore,
affected by Microsoft Internet Explorer 7 through 11 and Microsoft
Edge allow remote attackers to bypass the ASLR protection mechanism
via a crafted web site, aka 'Microsoft Browser ASLR Bypass'.
An unauthenticated, remote attacker can exploit this issue by
convincing a user to visit a specially craftedwebsite, resulting in
the execution of arbitrary code in the context of the current user.

A specific Fix to Run from Microsoft or a registry value must be added
to enable the fix for CVE-2015-6161.");
  # https://docs.microsoft.com/en-us/security-updates/SecurityBulletins/2015/ms15-124
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f205555e");
  # https://support.microsoft.com/en-us/help/3125869/ms15-124-vulnerability-in-internet-explorer-could-lead-to-aslr-bypass
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?43c16242");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows Vista, 2008, 7,
2008 R2, 8, RT, 2012, 8.1, RT 8.1, 2012 R2, and 10.

Refer to KB3125869 for additional information.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:L/UI:N/S:U/C:L/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2015-6161");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/12/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/12/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/03/02");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:ie");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2015-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("smb_hotfixes.nasl", "ms_bulletin_checks_possible.nasl");
  script_require_keys("SMB/MS_Bulletin_Checks/Possible");
  script_require_ports(139, 445, "Host/patch_management_checks");

  exit(0);
}

include('smb_hotfixes_fcheck.inc');
include('smb_hotfixes.inc');
include('smb_func.inc');
include('smb_reg_query.inc');
include('debug.inc');

get_kb_item_or_exit("SMB/MS_Bulletin_Checks/Possible");

bulletin = 'MS15-124';
kbs = make_list('3125869');

if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_WARNING);

get_kb_item_or_exit("SMB/Registry/Enumerated");
os = get_kb_item_or_exit("SMB/WindowsVersion", exit_code:1);
os_build = get_kb_item("SMB/WindowsVersionBuild");

if (hotfix_check_sp_range(vista:'2', win7:'1', win8:'0', win81:'0', win10:'0') <= 0) audit(AUDIT_OS_SP_NOT_VULN);
if ("10" >< os && !("10240" == os_build || "10586" == os_build)) audit(AUDIT_OS_SP_NOT_VULN);
if (hotfix_check_server_core() == 1) audit(AUDIT_WIN_SERVER_CORE);


##
# Validates content of Registry keys for x86 and x64 systems
# 
# Get registry keys values
# 1. 32bit hardening
# 2. 64bit hardening
#
# @return [boolean] True if enabled False if not enabled
##

function is_handler_fix_enabled()
{
  if (hotfix_check_server_core() == 1)
    return FALSE;

  local_var keyx86 = "SOFTWARE\Microsoft\Internet Explorer\MAIN\FeatureControl\FEATURE_ALLOW_USER32_EXCEPTION_HANDLER_HARDENING\iexplore.exe";
  local_var keyx64 = "SOFTWARE\Wow6432Node\Microsoft\Internet Explorer\MAIN\FeatureControl\FEATURE_ALLOW_USER32_EXCEPTION_HANDLER_HARDENING\iexplore.exe";
  registry_init();
  local_var result = check_handler_fix(key:keyx86);
  local_var ret_result = TRUE;
  local_var report = '';
  if(result != 'set')
  {
    report += '\n  The following registry key is ' + result + '\n  ';
    report += 'This registry key is required to enable the fix for CVE-2015-6161:\n  ';
    report += 'HKLM\\' + keyx86;
    report += '\n';
    ret_result = FALSE;
  }
  local_var arch = get_kb_item('SMB/ARCH');
  if(!isnull(arch) && arch == 'x64')
  {
    local_var x64result = check_handler_fix(key:keyx64);
    if(x64result != 'set')
    {
      report += '\n  The following registry key is ' + x64result + '\n  ';
      report += 'This registry key is required to enable the fix for CVE-2015-6161:\n  ';
      report += 'HKLM\\' + keyx64;
      report += '\n';
      ret_result = FALSE;
    }

  }
  close_registry();
  # If we know that either of the registry is not correct we log.
  if(!ret_result)
  { 
    hotfix_add_report(bulletin:'MS15-124', kb:'3125869', report);
    set_kb_item(name:'SMB/Superseded_Override/MS15-124/3125869', value:TRUE);
  }

  return ret_result;
}

##
# Given a registry key it validates if the key exists, content is empty or null or properly set
#
# @param key Registry Key for validation
#
# @return [boolean] True if enabled False if not enabled
##

function check_handler_fix(key)
{
  local_var hklm = registry_hive_connect(hive:HKEY_LOCAL_MACHINE, exit_on_fail:TRUE);
  local_var key_h = get_registry_value(handle:hklm, item:key);
  RegCloseKey(handle:hklm);
  if(isnull(key_h))
    return 'missing.\n';
  else if(key_h == 0)
    return 'not enabled.\n';
  else
    return 'set';
}

######################################
# Start normal checks
######################################
share = hotfix_get_systemdrive(as_share:TRUE, exit_on_fail:TRUE);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

# Assume applied until proven guilty
applied = TRUE;
if (
  # Windows 10
  hotfix_is_vulnerable(os:"10", sp:0, os_build:"10586", file:"mshtml.dll", version:"11.0.10586.20", min_version:"11.0.10586.0", dir:"\system32", bulletin:bulletin, kb:"3116900") ||
  hotfix_is_vulnerable(os:"10", sp:0, os_build:"10240", file:"mshtml.dll", version:"11.0.10240.16603", min_version:"11.0.10240.16000", dir:"\system32", bulletin:bulletin, kb:"3116869") ||

  # Windows 8.1 / Windows Server 2012 R2
  # Internet Explorer 11
  hotfix_is_vulnerable(os:"6.3", sp:0, file:"mshtml.dll", version:"11.0.9600.18125", min_version:"11.0.9600.17000", dir:"\system32", bulletin:bulletin, kb:"3104002") ||

  # Windows 8 / Windows Server 2012
  # Internet Explorer 10
  hotfix_is_vulnerable(os:"6.2", sp:0, file:"mshtml.dll", version:"10.0.9200.21684", min_version:"10.0.9200.21000", dir:"\system32", bulletin:bulletin, kb:"3104002") ||
  hotfix_is_vulnerable(os:"6.2", sp:0, file:"mshtml.dll", version:"10.0.9200.17568", min_version:"10.0.9200.16000", dir:"\system32", bulletin:bulletin, kb:"3104002") ||

  # Windows 7 / Server 2008 R2
  # Internet Explorer 10
  hotfix_is_vulnerable(os:"6.1", sp:1, file:"mshtml.dll", version:"10.0.9200.21684", min_version:"10.0.9200.21000", dir:"\system32", bulletin:bulletin, kb:"3104002") ||
  hotfix_is_vulnerable(os:"6.1", sp:1, file:"mshtml.dll", version:"10.0.9200.17566", min_version:"10.0.9200.16000", dir:"\system32", bulletin:bulletin, kb:"3104002") ||
  # Internet Explorer 11
  hotfix_is_vulnerable(os:"6.1", sp:1, file:"mshtml.dll", version:"11.0.9600.18125", min_version:"11.0.9600.17000", dir:"\system32", bulletin:bulletin, kb:"3104002") ||
  # Internet Explorer 8
  hotfix_is_vulnerable(os:"6.1", sp:1, file:"mshtml.dll", version:"8.0.7601.23262", min_version:"8.0.7601.22000", dir:"\system32", bulletin:bulletin, kb:"3104002") ||
  hotfix_is_vulnerable(os:"6.1", sp:1, file:"mshtml.dll", version:"8.0.7601.19058", min_version:"8.0.7601.17000", dir:"\system32", bulletin:bulletin, kb:"3104002") ||
  # Internet Explorer 9
  hotfix_is_vulnerable(os:"6.1", sp:1, file:"mshtml.dll", version:"9.0.8112.20838", min_version:"9.0.8112.20000", dir:"\system32", bulletin:bulletin, kb:"3104002") ||
  hotfix_is_vulnerable(os:"6.1", sp:1, file:"mshtml.dll", version:"9.0.8112.16723", min_version:"9.0.8112.16000", dir:"\system32", bulletin:bulletin, kb:"3104002") ||

  # Vista / Windows Server 2008
  # Internet Explorer 7
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"mshtml.dll", version:"7.0.6002.23847", min_version:"7.0.6002.23000", dir:"\system32", bulletin:bulletin, kb:"3104002") ||
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"mshtml.dll", version:"7.0.6002.19537", min_version:"7.0.6002.18000", dir:"\system32", bulletin:bulletin, kb:"3104002") ||
  # Internet Explorer 8
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"mshtml.dll", version:"8.0.6001.23765", min_version:"8.0.6001.23000", dir:"\system32", bulletin:bulletin, kb:"3104002") ||
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"mshtml.dll", version:"8.0.6001.19705", min_version:"8.0.6001.18000", dir:"\system32", bulletin:bulletin, kb:"3104002") ||
  # Internet Explorer 9
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"mshtml.dll", version:"9.0.8112.20838", min_version:"9.0.8112.20000", dir:"\system32", bulletin:bulletin, kb:"3104002") ||
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"mshtml.dll", version:"9.0.8112.16723", min_version:"9.0.8112.16000", dir:"\system32", bulletin:bulletin, kb:"3104002")
) applied = FALSE;


######################################
# Check registry keys values
######################################
harden = is_handler_fix_enabled();

######################################
# Report
######################################
if (!applied || !harden)
{
  set_kb_item(name:'SMB/Missing/'+bulletin, value:TRUE);
  hotfix_security_warning();
  hotfix_check_fversion_end();
  exit(0);
}
else
{
  hotfix_check_fversion_end();
  audit(AUDIT_HOST_NOT, 'affected');
}