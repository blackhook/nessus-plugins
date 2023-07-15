#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(154032);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/01/26");

  script_cve_id("CVE-2021-41342");
  script_xref(name:"MSKB", value:"5006671");
  script_xref(name:"MSKB", value:"5006714");
  script_xref(name:"MSKB", value:"5006736");
  script_xref(name:"MSKB", value:"5006739");
  script_xref(name:"MSKB", value:"5006743");
  script_xref(name:"MSFT", value:"MS21-5006671");
  script_xref(name:"MSFT", value:"MS21-5006714");
  script_xref(name:"MSFT", value:"MS21-5006736");
  script_xref(name:"MSFT", value:"MS21-5006739");
  script_xref(name:"MSFT", value:"MS21-5006743");
  script_xref(name:"IAVA", value:"2021-A-0472-S");
  script_xref(name:"IAVA", value:"2021-A-0475-S");

  script_name(english:"Security Updates for Internet Explorer (October 2021)");

  script_set_attribute(attribute:"synopsis", value:
"The Internet Explorer installation on the remote host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The Internet Explorer installation on the remote host is missing a security update. It is, therefore, affected by a
remote code execution vulnerability in the MSHTML platform. An unauthenticated, remote attacker can exploit this to
bypass authentication and execute arbitrary commands.");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/topic/5006671");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/topic/5006714");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/topic/5006736");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/topic/5006739");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/topic/5006743");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released the following security updates to address this issue:  
  -KB5006671
  -KB5006714
  -KB5006736
  -KB5006739
  -KB5006743");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-41342");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/10/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/10/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/10/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:ie");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2021-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("smb_check_rollup.nasl", "smb_hotfixes.nasl", "ms_bulletin_checks_possible.nasl");
  script_require_keys("SMB/MS_Bulletin_Checks/Possible");
  script_require_ports(139, 445, "Host/patch_management_checks");

  exit(0);
}
include("smb_hotfixes_fcheck.inc");
include("smb_hotfixes.inc");
include("smb_func.inc");

get_kb_item_or_exit("SMB/MS_Bulletin_Checks/Possible");

var bulletin = 'MS21-10';
var kbs = make_list(
  '5006671',
  '5006714',
  '5006736',
  '5006739',
  '5006743'
);

if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_WARNING);

get_kb_item_or_exit("SMB/Registry/Enumerated");
var os = get_kb_item_or_exit("SMB/WindowsVersion", exit_code:1);

if (hotfix_check_sp_range(vista:'2', win7:'1', win8:'0',  win81:'0') <= 0) audit(AUDIT_OS_SP_NOT_VULN);

var productname = get_kb_item_or_exit("SMB/ProductName", exit_code:1);
if ("Windows 8" >< productname && "8.1" >!< productname)
 audit(AUDIT_OS_SP_NOT_VULN);
if ("Vista" >< productname) audit(AUDIT_OS_SP_NOT_VULN);

if (hotfix_check_server_core() == 1) audit(AUDIT_WIN_SERVER_CORE);

var share = hotfix_get_systemdrive(as_share:TRUE, exit_on_fail:TRUE);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

if (
  # Windows 8.1 / Windows Server 2012 R2
  # Internet Explorer 11
  hotfix_is_vulnerable(os:"6.3", sp:0, file:"mshtml.dll", version:"11.0.9600.20139", min_version:"11.0.9600.16000", dir:"\system32", bulletin:bulletin, kb:"5006671") ||

  # Windows Server 2012
  # Internet Explorer 11
  hotfix_is_vulnerable(os:"6.2", sp:0, file:"mshtml.dll", version:"11.0.9600.20139", min_version:"11.0.9600.16000", dir:"\system32", bulletin:bulletin, kb:"5006671") ||

  # Windows 7 / Server 2008 R2
  # Internet Explorer 11
  hotfix_is_vulnerable(os:"6.1", sp:1, file:"mshtml.dll", version:"11.0.9600.20139", min_version:"11.0.9600.16000", dir:"\system32", bulletin:bulletin, kb:"5006671") ||

  # Windows Server 2008
  # Internet Explorer 9
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"mshtml.dll", version:"9.0.8112.21601", min_version:"9.0.8112.16000", dir:"\system32", bulletin:bulletin, kb:"5006671")
)
{
  var report =  '\nNote: The fix for this issue is available in either of the following updates:\n';
  report += '  - KB5006671 : Cumulative Security Update for Internet Explorer\n';

  if(os == "6.3")
  {
    report += '  - KB5006714 : Windows 8.1 / Server 2012 R2 Monthly Rollup\n';
    hotfix_add_report(bulletin:bulletin, kb:'5006714', report);
  }
  else if(os == "6.2")
  {
    report += '  - KB5006739 : Windows Server 2012 Monthly Rollup\n';
    hotfix_add_report(bulletin:bulletin, kb:'5006739', report);
  }
  else if(os == "6.1")
  {
    report += '  - KB5006743 : Windows 7 / Server 2008 R2 Monthly Rollup\n';
    hotfix_add_report(bulletin:bulletin, kb:'5006743', report);
  }
  else if(os == "6.0")
  {
    report += '  - KB5006736 : Windows Server 2008 Monthly Rollup\n';
    hotfix_add_report(bulletin:bulletin, kb:'5006736', report);
  }

  set_kb_item(name:'SMB/Missing/'+bulletin, value:TRUE);

  var port = kb_smb_transport();

  hotfix_security_warning();
  hotfix_check_fversion_end();
}
else
{
  hotfix_check_fversion_end();
  audit(AUDIT_HOST_NOT, hotfix_get_audit_report());
}

