#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(104043);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/09/04");

  script_cve_id("CVE-2017-0184");
  script_bugtraq_id(97435);
  script_xref(name:"MSKB", value:"3217841");
  script_xref(name:"MSFT", value:"MS17-3217841");

  script_name(english:"KB3217841: Security Update for the Hyper-V Denial of Service Vulnerability (April 2017)");
  script_summary(english:"Checks the file versions.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host is affected by an information disclosure
vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote Windows host is missing a security update KB3217841. It is,
therefore, affected by a denial of service vulnerability in Hyper-V
due to improper validation of input from a privileged user on a guest 
operating system.");
  # https://support.microsoft.com/en-us/help/3217841/security-update-for-the-hyper-v-denial-of-service-vulnerability
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b2a99b49");
  # https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/CVE-2017-0184
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f8013000");
  script_set_attribute(attribute:"solution", value:
"Apply security update KB3217841.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:M/Au:S/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:H/PR:H/UI:N/S:C/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-0184");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/04/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/04/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/10/20");

  script_set_attribute(attribute:"plugin_type",value:"local");
  script_set_attribute(attribute:"cpe",value:"cpe:/o:microsoft:windows");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2017-2020 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl", "wmi_enum_server_features.nbin", "ms_bulletin_checks_possible.nasl");
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
kbs = make_list('3217841');

if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_WARNING);

get_kb_item_or_exit("SMB/Registry/Enumerated");
get_kb_item_or_exit("SMB/WindowsVersion", exit_code:1);

if (hotfix_check_sp_range(vista:'2') <= 0)
  audit(AUDIT_OS_SP_NOT_VULN);

# If Hyper-V is not enabled, the software cannot be exploited.  However, the
# software is still technically vulnerable.  The MS bulletin states:
#
#   This update can be installed manually on affected
#   platforms even if the Hyper-V role is not enabled.
#
# Therefore, we'll check for the patch unconditionally during paranoid scans.
#
# (Hyper-V ID = 20)
#
if (!get_kb_item('WMI/server_feature/20') && report_paranoia < 2)
  exit(0, 'Hyper-V is not enabled, therefore the host is not affected.');


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

files = list_dir(basedir:winsxs, level:0, dir_pat:"wstorvsp.inf_31bf3856ad364e35", file_pat:"^storvsp\.sys$", max_recurse:1);
vuln += hotfix_check_winsxs(
  os:'6.0',
  sp:2,
  files:files,
  versions:make_list('6.0.6002.19728', '6.0.6002.24078'),
  max_versions:make_list('6.0.6002.24051', '6.0.6003.99999'),
  bulletin:bulletin,
  kb:"3217841",
  session:smb_session
);

if (vuln > 0)
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
