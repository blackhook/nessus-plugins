#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(104044);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/11/30");

  script_cve_id("CVE-2017-0199");
  script_bugtraq_id(97498);
  script_xref(name:"MSKB", value:"4014793");
  script_xref(name:"MSFT", value:"MS17-4014793");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/05/03");

  script_name(english:"KB4014793: Microsoft Wordpad Remote Code Execution vulnerability (April 2017)");
  script_summary(english:"Checks the Wordpad.exe file version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host is affected by an information disclosure
vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote Windows host is missing security update KB4014793. It is, 
therefore, affected by a remote code execution vulnerability in Windows 
WordPad due to improper validation of user-supplied input. 
An unauthenticated, remote attacker can exploit this, by convincing a 
user to open a specially crafted file, to execute arbitrary code.");
  # https://support.microsoft.com/en-us/help/4014793/title
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b841e949");
  # https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/CVE-2017-0199
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?7d5b7803");
  script_set_attribute(attribute:"solution", value:
"Apply security update KB4014793.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-0199");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Microsoft Office Word Malicious Hta Execution');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/04/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/04/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/10/20");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2017-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

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

bulletin = 'MS17-04';
kbs = make_list("4014793");

if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

get_kb_item_or_exit("SMB/Registry/Enumerated");
get_kb_item_or_exit("SMB/WindowsVersion", exit_code:1);

if (hotfix_check_sp_range(vista:'2') <= 0)
  audit(AUDIT_OS_SP_NOT_VULN);

share = hotfix_get_systemdrive(as_share:TRUE, exit_on_fail:TRUE);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

systemroot = hotfix_get_systemroot();
if (!systemroot) audit(AUDIT_PATH_NOT_DETERMINED, 'system root');

port = kb_smb_transport();
login  = kb_smb_login();
pass   = kb_smb_password();
domain = kb_smb_domain();

if (hotfix_check_fversion_init() == HCF_CONNECT) exit(0, "Unable to create SMB session.");

winsxs = ereg_replace(pattern:'^[A-Za-z]:(.*)', replace:"\1\WinSxS", string:systemroot);
winsxs_share = hotfix_path2share(path:systemroot);

rc = NetUseAdd(login:login, password:pass, domain:domain, share:winsxs_share);
if (rc != 1)
{
  NetUseDel();
  audit(AUDIT_SHARE_FAIL, winsxs_share);
}

vuln = 0;

# hotfix_check_winsxs opens another share
# we need to save state so our session can be restored
smb_session = make_array(
  'login',    login,
  'password', pass,
  'domain',   domain,
  'share',    winsxs_share
);

files = list_dir(basedir:winsxs, level:0, dir_pat:"microsoft-windows-wordpad", file_pat:"^wordpad\.exe$", max_recurse:1);
vuln += hotfix_check_winsxs(
  os:'6.0',
  sp:2,
  files:files,
  versions:make_list('6.0.6002.19755', '6.0.6002.24078'),
  max_versions:make_list('6.0.6002.21000', '6.0.6003.99999'),
  bulletin:bulletin,
  kb:"4014793",
  session:smb_session
);

if (vuln > 0)
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
