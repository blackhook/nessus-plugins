#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(90437);
  script_version("1.10");
  script_cvs_date("Date: 2019/11/20");

  script_cve_id("CVE-2016-0153");
  script_bugtraq_id(85912);
  script_xref(name:"MSFT", value:"MS16-044");
  script_xref(name:"MSKB", value:"3146706");
  script_xref(name:"IAVB", value:"2016-B-0068");

  script_name(english:"MS16-044: Security Update for Windows OLE (3146706)");
  script_summary(english:"Checks the file version of ole32.dll.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host is affected by a remote code execution
vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote Windows host is missing a security update. It is,
therefore, affected by a remote code execution vulnerability in
Windows OLE due to improper validation of user-supplied input. An
unauthenticated, remote attacker can exploit this vulnerability by
convincing a user to open a specially crafted file, resulting in the
execution of arbitrary code in the context of the current user.");
  script_set_attribute(attribute:"see_also", value:"https://docs.microsoft.com/en-us/security-updates/SecurityBulletins/2016/ms16-044");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows Vista, 2008, 7,
2008 R2, 2012, 8.1, RT 8.1, and 2012 R2.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2016-0153");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/04/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/04/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/04/12");

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

bulletin = 'MS16-044';

kbs = make_list('3146706');
if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

get_kb_item_or_exit("SMB/Registry/Enumerated");
get_kb_item_or_exit("SMB/WindowsVersion", exit_code:1);

if (hotfix_check_sp_range(vista:'2', win7:'1', win8:'0', win81:'0') <= 0)
  audit(AUDIT_OS_SP_NOT_VULN);

# Windows 8 EOL
productname = get_kb_item_or_exit("SMB/ProductName", exit_code:1);
if ("Windows 8" >< productname && "8.1" >!< productname) audit(AUDIT_OS_SP_NOT_VULN);

share = hotfix_get_systemdrive(as_share:TRUE, exit_on_fail:TRUE);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

if (
  # Vista / Windows Server 2008
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"ole32.dll", version:"6.0.6002.23936", min_version:"6.0.6002.23000", dir:"\system32", bulletin:bulletin, kb:"3146706") ||
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"ole32.dll", version:"6.0.6002.19623", min_version:"6.0.6001.18000", dir:"\system32", bulletin:bulletin, kb:"3146706") ||

  # Windows 7 / Server 2008 R2
  hotfix_is_vulnerable(os:"6.1", sp:1, file:"ole32.dll", version:"6.1.7601.23392", min_version:"6.1.7600.16000", dir:"\system32", bulletin:bulletin, kb:"3146706") ||

  # Windows 8.1 / Windows Server 2012 R2
  hotfix_is_vulnerable(os:"6.3", sp:0, file:"ole32.dll", version:"6.3.9600.18256", min_version:"6.3.9600.16000", dir:"\system32", bulletin:bulletin, kb:"3146706") ||

  # Windows Server 2012
  hotfix_is_vulnerable(os:"6.2", sp:0, file:"ole32.dll", version:"6.2.9200.21792", min_version:"6.2.9200.16000", dir:"\system32", bulletin:bulletin, kb:"3146706")
)
{
  set_kb_item(name:'SMB/Missing/'+bulletin, value:TRUE);
  hotfix_security_hole();
  hotfix_check_fversion_end();
}
else
{
  hotfix_check_fversion_end();
  audit(AUDIT_HOST_NOT, 'affected');
}
