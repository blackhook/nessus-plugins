#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(91603);
  script_version("1.13");
  script_cvs_date("Date: 2019/11/19");

  script_cve_id("CVE-2016-3225");
  script_bugtraq_id(91080);
  script_xref(name:"MSFT", value:"MS16-075");
  script_xref(name:"MSKB", value:"3161561");
  script_xref(name:"MSKB", value:"3163017");
  script_xref(name:"MSKB", value:"3163018");
  script_xref(name:"IAVA", value:"2016-A-0150");

  script_name(english:"MS16-075: Security Update for Windows SMB Server (3164038)");
  script_summary(english:"Checks the version of the SYS files.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host is affected by an elevation of privilege
vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote Windows host is missing a security update. It is,
therefore, affected by an elevation of privilege vulnerability in the
Microsoft Server Message Block (SMB) server when handling forwarded
credential requests that are intended for another service running
on the same host. An authenticated attacker can exploit this, via a
specially crafted application, to execute arbitrary code with elevated
permissions.");
  script_set_attribute(attribute:"see_also", value:"https://docs.microsoft.com/en-us/security-updates/SecurityBulletins/2016/ms16-075");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows Vista, 2008, 7,
2008 R2, 2012, 8.1, RT 8.1, 2012 R2, and 10.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2016-3225");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Windows Net-NTLMv2 Reflection DCOM/RPC (Juicy)');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/06/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/06/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/06/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2016-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("smb_hotfixes.nasl", "ms_bulletin_checks_possible.nasl");
  script_require_keys("SMB/MS_Bulletin_Checks/Possible");
  script_require_ports(139, 445, "Host/patch_management_checks");

  exit(0);
}

include("audit.inc");
include("smb_hotfixes_fcheck.inc");
include("smb_hotfixes.inc");
include("smb_func.inc");
include("misc_func.inc");

get_kb_item_or_exit("SMB/MS_Bulletin_Checks/Possible");

bulletin = 'MS16-075';
kbs = make_list(
    "3161561",
    "3163017",
    "3163018"
);

vuln = 0;

if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_WARNING);

get_kb_item_or_exit("SMB/Registry/Enumerated");
get_kb_item_or_exit("SMB/WindowsVersion", exit_code:1);

if (hotfix_check_sp_range(vista:'2', win7:'1', win8:'0', win81:'0', win10:'0') <= 0)
  audit(AUDIT_OS_SP_NOT_VULN);

productname = get_kb_item_or_exit("SMB/ProductName", exit_code:1);
if ("Windows 8" >< productname && "Windows 8.1" >!< productname)
  audit(AUDIT_OS_SP_NOT_VULN);


share = hotfix_get_systemdrive(as_share:TRUE, exit_on_fail:TRUE);
if (!is_accessible_share(share:share))
  audit(AUDIT_SHARE_FAIL, share);

kb = "3161561";
if (
  # Windows Vista Service Pack 2 / Windows Server 2008
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"srvnet.sys", version:"6.0.6002.19659", min_version:"6.0.6002.18000", dir:"\system32\drivers", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"srvnet.sys", version:"6.0.6002.23974", min_version:"6.0.6002.20000", dir:"\system32\drivers", bulletin:bulletin, kb:kb) ||

  # Windows 7 / Windows Server 2008 R2
  hotfix_is_vulnerable(os:"6.1", sp:1, file:"srvnet.sys", version:"6.1.7601.23452", min_version:"6.1.7600.16000", dir:"\system32\drivers", bulletin:bulletin, kb:kb) ||

  # Windows Server 2012
  hotfix_is_vulnerable(os:"6.2", sp:0, file:"srvnet.sys", version:"6.2.9200.21860", min_version:"6.2.9200.16000", dir:"\system32\drivers", bulletin:bulletin, kb:kb) ||

  # Windows 8.1 / Windows Server 2012 R2
  hotfix_is_vulnerable(os:"6.3", sp:0, file:"srvnet.sys", version:"6.3.9600.18340", min_version:"6.3.9600.16000", dir:"\system32\drivers", bulletin:bulletin, kb:kb)
)
  vuln++;

kb = "3163017";
if (
  # Windows 10
  hotfix_is_vulnerable(os:"10", sp:0, file:"srvnet.sys", version:"10.0.10240.16942", min_version:"10.0.10240.0", dir:"\system32\drivers", bulletin:bulletin, kb:kb)
)
  vuln++;

kb = "3163018";
if (
  # Windows 10 1511
  hotfix_is_vulnerable(os:"10", sp:0, file:"srvnet.sys", version:"10.0.10586.420", min_version:"10.0.10586.0", dir:"\system32\drivers", bulletin:bulletin, kb:kb)
)
  vuln++;


if (vuln)
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
