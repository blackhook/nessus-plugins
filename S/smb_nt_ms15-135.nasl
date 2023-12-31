#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(87264);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/25");

  script_cve_id(
    "CVE-2015-6171",
    "CVE-2015-6173",
    "CVE-2015-6174",
    "CVE-2015-6175"
  );
  script_bugtraq_id(
    78506,
    78510,
    78513,
    78514
  );
  script_xref(name:"MSFT", value:"MS15-135");
  script_xref(name:"MSKB", value:"3109094");
  script_xref(name:"MSKB", value:"3116869");
  script_xref(name:"MSKB", value:"3116900");
  script_xref(name:"IAVA", value:"2015-A-0299");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/06/15");

  script_name(english:"MS15-135: Security Update for Windows Kernel-Mode Drivers to Address Elevation of Privilege (3119075)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host is affected by multiple elevation of privilege
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote Windows host is affected by multiple elevation of privilege
vulnerabilities due to improper handling of objects in memory by the
Windows kernel. An authenticated, remote attacker can exploit these
vulnerabilities by running a specially crafted application, resulting
in an elevation of privileges.");
  script_set_attribute(attribute:"see_also", value:"https://docs.microsoft.com/en-us/security-updates/SecurityBulletins/2015/ms15-135");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows Vista, 2008, 7,
2008 R2, 8, RT, 2012, 8.1, RT 8.1, 2012 R2, and 10.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2015-6175");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/12/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/12/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/12/08");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2015-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

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

bulletin = 'MS15-135';
kbs = make_list(
    "3109094",
    "3116869",
    "3116900"
);
vuln = 0;

if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

get_kb_item_or_exit("SMB/Registry/Enumerated");
get_kb_item_or_exit("SMB/WindowsVersion", exit_code:1);

if (hotfix_check_sp_range(vista:'2', win7:'1', win8:'0', win81:'0', win10:'0') <= 0) audit(AUDIT_OS_SP_NOT_VULN);

share = hotfix_get_systemdrive(as_share:TRUE, exit_on_fail:TRUE);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

if (
  # 8.1 / 2012 R2
  hotfix_is_vulnerable(os:"6.3", sp:0, file:"win32k.sys", version:"6.3.9600.18123", min_version:"6.3.9600.16000", dir:"\system32", bulletin:bulletin, kb:"3109094") ||
  # 8 / 2012
  hotfix_is_vulnerable(os:"6.2", sp:0, file:"win32k.sys", version:"6.2.9200.17568", min_version:"6.2.9200.16000", dir:"\system32", bulletin:bulletin, kb:"3109094") ||
  hotfix_is_vulnerable(os:"6.2", sp:0, file:"win32k.sys", version:"6.2.9200.21687", min_version:"6.2.9200.20000 ", dir:"\system32", bulletin:bulletin, kb:"3109094") ||
  # 7 / 2008 R2
  hotfix_is_vulnerable(os:"6.1", sp:1, file:"win32k.sys", version:"6.1.7601.19061", min_version:"6.1.7600.18000", dir:"\system32", bulletin:bulletin, kb:"3109094") ||
  hotfix_is_vulnerable(os:"6.1", sp:1, file:"win32k.sys", version:"6.1.7601.23265", min_version:"6.1.7601.22000", dir:"\system32", bulletin:bulletin, kb:"3109094") ||
  # Vista / 2008
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"win32k.sys", version:"6.0.6002.19535", min_version:"6.0.6002.18000", dir:"\system32", bulletin:bulletin, kb:"3109094") ||
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"win32k.sys", version:"6.0.6002.23845", min_version:"6.0.6002.20000", dir:"\system32", bulletin:bulletin, kb:"3109094")
)
  vuln++;

if (
  # 10 RTM
  hotfix_is_vulnerable(os:"10", sp:0, file:"win32kfull.sys", version:"10.0.10240.16603", dir:"\system32", bulletin:bulletin, kb:"3116869") ||
  # 10 threshold 2 (aka 1511)
  hotfix_is_vulnerable(os:"10", sp:0, file:"win32kfull.sys", version:"10.0.10586.20", min_version:"10.0.10586.0", dir:"\system32", bulletin:bulletin, kb:"3116900")
)
  vuln++;

if (vuln)
{
  set_kb_item(name:'SMB/Missing/'+bulletin, value:TRUE);
  hotfix_security_hole();
  hotfix_check_fversion_end();
  exit(0);
}
else
{
  hotfix_check_fversion_end();
  audit(AUDIT_HOST_NOT, 'affected');
}
