#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(92018);
  script_version("1.13");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/09/04");

  script_cve_id("CVE-2016-3238", "CVE-2016-3239");
  script_bugtraq_id(91609, 91612);
  script_xref(name:"MSFT", value:"MS16-087");
  script_xref(name:"MSKB", value:"3170455");
  script_xref(name:"MSKB", value:"4038777");
  script_xref(name:"MSKB", value:"4038779");
  script_xref(name:"MSKB", value:"4038781");
  script_xref(name:"MSKB", value:"4038782");
  script_xref(name:"MSKB", value:"4038783");
  script_xref(name:"MSKB", value:"4038786");
  script_xref(name:"MSKB", value:"4038792");
  script_xref(name:"MSKB", value:"4038793");
  script_xref(name:"MSKB", value:"4038799");
  script_xref(name:"IAVA", value:"2016-A-0181");

  script_name(english:"MS16-087: Security Update for Windows Print Spooler (3170005)");
  script_summary(english:"Checks the version of ntprint.dll and localspl.dll.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote Windows host is missing a security update. It is,
therefore, affected by multiple vulnerabilities :

  - A remote code execution vulnerability exists in the
    Windows Print Spooler service due to improper validation
    of print drivers while installing a printer from network
    servers. An unauthenticated, remote attacker can exploit
    this vulnerability, via a man-in-the-middle attack on a
    workstation or print server or via a rogue print server,
    to execute arbitrary code in the context of the current
    user. (CVE-2016-3238)

  - An elevation of privilege vulnerability exists in the
    Windows Print Spooler service due to improperly allowing
    arbitrary writing to the file system. An attacker can
    exploit this issue, via a specially crafted script or
    application, to execute arbitrary code with elevated
    system privileges. (CVE-2016-3239)");
  # https://docs.microsoft.com/en-us/security-updates/SecurityBulletins/2016/ms16-087
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?fad1285c");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows Vista, 2008, 7,
2008 R2, 2012, 8.1, RT 8.1, 2012 R2, and 10.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2016-3238");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/07/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/07/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/07/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2016-2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("smb_hotfixes.nasl", "ms_bulletin_checks_possible.nasl", "smb_check_rollup.nasl");
  script_require_keys("SMB/MS_Bulletin_Checks/Possible");
  script_require_ports(139, 445, "Host/patch_management_checks");

  exit(0);
}

include("audit.inc");
include("smb_hotfixes_fcheck.inc");
include("smb_hotfixes.inc");
include("smb_func.inc");
include("smb_reg_query.inc");
include("misc_func.inc");

get_kb_item_or_exit("SMB/MS_Bulletin_Checks/Possible");

bulletin = 'MS16-087';
kbs = make_list(
    '3170455', # Vista / 2008
    '4038777', # 7 / 2008 R2 - Monthly
    '4038779', # 7 / 2008 R2 - Security
    '4038781', # Win 10
    '4038782', # Win 10 1607
    '4038783', # Win 10 1511
    '4038786', # 2012 - Security
    '4038792', # 8.1 / 2012 R2 - Monthly
    '4038793', # 8.1 / 2012 R2 - Security
    '4038799'  # 2012 - Monthly
);

vuln = FALSE;
sxs_vuln = FALSE;

if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

get_kb_item_or_exit("SMB/Registry/Enumerated");
get_kb_item_or_exit('SMB/WindowsVersion', exit_code:1);

if (hotfix_check_sp_range(vista:'2', win7:'1', win8:'0', win81:'0', win10:'0') <= 0) audit(AUDIT_OS_SP_NOT_VULN);
productname = get_kb_item_or_exit("SMB/ProductName", exit_code:1);
if ("Windows 8" >< productname && "Windows 8.1" >!< productname) audit(AUDIT_OS_SP_NOT_VULN);

if (hotfix_check_server_nano() == 1) audit(AUDIT_OS_NOT, "a currently supported OS (Windows Nano Server)");

if (hotfix_check_server_core() == 1)
{
  #check to see if Printing-ServerCore-Role is enabled
  registry_init();
  hcf_init = TRUE;
  hklm = registry_hive_connect(hive:HKEY_LOCAL_MACHINE, exit_on_fail:TRUE);
  dval = get_registry_value(handle:hklm, item:"SOFTWARE\Policies\Microsoft\Windows NT\Printers\RegisterSpoolerRemoteRpcEndPoint");
  RegCloseKey(handle:hklm);
  close_registry(close:TRUE);

  # if dval == 0, then the system is not vulnerable
  if (!dval) audit(AUDIT_HOST_NOT, 'affected');
}

systemroot = hotfix_get_systemroot();
if (!systemroot) audit(AUDIT_PATH_NOT_DETERMINED, 'system root');

port   = kb_smb_transport();
login  = kb_smb_login();
pass   = kb_smb_password();
domain = kb_smb_domain();

if(! smb_session_init()) audit(AUDIT_FN_FAIL, 'smb_session_init');

winsxs = ereg_replace(pattern:'^[A-Za-z]:(.*)', replace:"\1\WinSxS", string:systemroot);
winsxs_share = hotfix_path2share(path:systemroot);

rc = NetUseAdd(login:login, password:pass, domain:domain, share:winsxs_share);
if (rc != 1)
{
    NetUseDel();
      audit(AUDIT_SHARE_FAIL, winsxs_share);
}

files = list_dir(basedir:winsxs, level:0, dir_pat:"p..randprintui-ntprint", file_pat:"^ntprint\.dll$", max_recurse:1);

if (
  # Vista / Windows Server 2008 SxS
  hotfix_check_winsxs(os:'6.0',
    sp:2,
    files:files,
    versions:make_list('6.0.6002.19861', '6.0.6002.24182'),
    max_versions:make_list('6.0.6002.22000', '6.0.6003.99999'),
    bulletin:bulletin,
    kb:'3170455')
)
  sxs_vuln = TRUE;

NetUseDel();

share = hotfix_get_systemdrive(as_share:TRUE, exit_on_fail:TRUE);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

if (
  # 8.1 / 2012 R2 / RT 8.1
  smb_check_rollup(
    os:"6.3",
    sp:0,
    rollup_date: "09_2017",
    bulletin:bulletin,
    rollup_kb_list:make_list(4038792, 4038793)) ||

  # 2012
  smb_check_rollup(
    os:"6.2",
    sp:0,
    rollup_date: "04_2017",
    bulletin:bulletin,
    rollup_kb_list:make_list(4038799, 4038786)) ||

  # 7 / 2008 R2
  smb_check_rollup(
    os:"6.1",
    sp:1,
    rollup_date: "09_2017",
    bulletin:bulletin,
    rollup_kb_list:make_list(4038777, 4038779)) ||

#  # 10 (1507)
#  smb_check_rollup(
#    os:"10",
#    sp:0,
#    os_build:"10240",
#    rollup_date: "09_2017",
#    bulletin:bulletin,
#    rollup_kb_list:make_list(4038781)) || # Does not apply per installer

  # Windows 10
  hotfix_is_vulnerable(os:"10", sp:0, file:"localspl.dll", version:"10.0.10240.17023", os_build:"10240", dir:"\system32", bulletin:bulletin, kb:"3163912") ||
  hotfix_is_vulnerable(os:"10", sp:0, file:"localspl.dll", version:"10.0.10586.494", os_build:"10586", dir:"\system32", bulletin:bulletin, kb:"3172985") ||

  # 10 1511 (AKA 10586)
  smb_check_rollup(
    os:"10",
    sp:0,
    os_build:"10586",
    rollup_date: "09_2017",
    bulletin:bulletin,
    rollup_kb_list:make_list(4038783)) ||

  # 10 1607 (AKA 14393) / Server 2016
  smb_check_rollup(
    os:"10",
    sp:0,
    os_build:"14393",
    rollup_date: "09_2017",
    bulletin:bulletin,
    rollup_kb_list:make_list(4038782))
)
  vuln = TRUE;

if (vuln || sxs_vuln)
{
  set_kb_item(name:"SMB/Missing/"+bulletin, value:TRUE);
  hotfix_security_hole();
  hotfix_check_fversion_end();
  exit(0);
}
else
{
  hotfix_check_fversion_end();
  audit(AUDIT_HOST_NOT, 'affected');
}
