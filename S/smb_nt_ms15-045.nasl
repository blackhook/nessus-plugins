#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(83362);
  script_version("1.9");
  script_cvs_date("Date: 2018/11/15 20:50:31");

  script_cve_id(
    "CVE-2015-1675",
    "CVE-2015-1695",
    "CVE-2015-1696",
    "CVE-2015-1697",
    "CVE-2015-1698",
    "CVE-2015-1699"
  );
  script_bugtraq_id(
    74493,
    74498,
    74499,
    74500,
    74501,
    74502
  );
  script_xref(name:"MSFT", value:"MS15-045");
  script_xref(name:"MSKB", value:"3046002");

  script_name(english:"MS15-045: Vulnerability in Windows Journal Could Allow Remote Code Execution (3046002)");
  script_summary(english:"Checks the file version of jnwdrv.dll.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host is affected by a remote code execution
vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Windows running on the remote host is affected by a
remote code execution vulnerability due to a flaw in Windows Journal.
A remote attacker can exploit this vulnerability by convincing a user
to open a specially crafted Journal file (.jnt), resulting in
execution of arbitrary code in the context of the current user.");
  script_set_attribute(attribute:"see_also", value:"https://docs.microsoft.com/en-us/security-updates/SecurityBulletins/2015/ms15-045");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows Vista, 2008, 7,
2008 R2, 8, 2012, 8.1, and 2012 R2");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/05/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/05/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/05/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2015-2018 Tenable Network Security, Inc.");

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

bulletin = 'MS15-045';
kb = '3046002';

kbs = make_list(kb);
if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

get_kb_item_or_exit("SMB/Registry/Enumerated");
get_kb_item_or_exit("SMB/WindowsVersion", exit_code:1);

if (hotfix_check_sp_range(vista:'2', win7:'1', win8:'0', win81:'0') <= 0) audit(AUDIT_OS_SP_NOT_VULN);

share = hotfix_get_systemdrive(as_share:TRUE, exit_on_fail:TRUE);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

commonfiles = hotfix_get_commonfilesdir();
if (!commonfiles) commonfiles = hotfix_get_commonfilesdirx86();

if (!commonfiles) audit(AUDIT_PATH_NOT_DETERMINED, 'Common Files');

journal_path = hotfix_append_path(path:commonfiles, value:"\microsoft shared\ink");

if (
  # Windows 8.1 / Windows Server 2012 R2
  hotfix_is_vulnerable(os:"6.3", sp:0, file:"Journal.dll", version:"6.3.9600.17793", min_version:"6.3.9600.17000", path:journal_path, bulletin:bulletin, kb:kb) ||
  # without KB2919355
  hotfix_is_vulnerable(os:"6.3", sp:0, file:"Journal.dll", version:"6.3.9600.16670", min_version:"6.3.9600.16000", path:journal_path, bulletin:bulletin, kb:kb) ||

  # Windows 8 / Windows Server 2012
  hotfix_is_vulnerable(os:"6.2", sp:0, file:"Journal.dll", version:"6.2.9200.21444", min_version:"6.2.9200.20000", path:journal_path, bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.2", sp:0, file:"Journal.dll", version:"6.2.9200.17330", min_version:"6.2.9200.16000", path:journal_path, bulletin:bulletin, kb:kb) ||

  # Windows 7 and Windows Server 2008 R2
  hotfix_is_vulnerable(os:"6.1", sp:1, file:"Journal.dll", version:"6.1.7601.23020", min_version:"6.1.7601.22000", path:journal_path, bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.1", sp:1, file:"Journal.dll", version:"6.1.7601.18815", min_version:"6.1.7600.16000", path:journal_path, bulletin:bulletin, kb:kb) ||

  # Vista / Windows 2008
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"Journal.dll", version:"6.0.6002.23664", min_version:"6.0.6002.23000", path:journal_path, bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"Journal.dll", version:"6.0.6002.19356", min_version:"6.0.6002.18000", path:journal_path, bulletin:bulletin, kb:kb)
)
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
