#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(93473);
  script_version("1.7");
  script_cvs_date("Date: 2018/11/15 20:50:32");
  script_cve_id("CVE-2016-3345");
  script_bugtraq_id(92859);
  script_xref(name:"MSFT", value:"MS16-114");
  script_xref(name:"MSKB", value:"3177186");
  script_xref(name:"MSKB", value:"3185611");
  script_xref(name:"MSKB", value:"3185614");
  script_xref(name:"MSKB", value:"3189866");
  script_xref(name:"IAVA", value:"2016-A-0248");

  script_name(english:"MS16-114: Security Update for Windows SMBv1 Server (3185879)");
  script_summary(english:"Checks the version of srv.sys.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by a remote code execution vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote Windows host is missing a security update. It is,
therefore, affected by a remote code execution vulnerability in the
Microsoft Server Message Block 1.0 (SMBv1) Server due to improper
handling of certain requests. An authenticated, remote attacker can
exploit this, via specially crafted packets, to cause a denial of
service condition or the execution of arbitrary code.");
  script_set_attribute(attribute:"see_also", value:"https://docs.microsoft.com/en-us/security-updates/SecurityBulletins/2016/ms16-114");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows Vista, 2008, 7,
2008 R2, 2012, 8.1, RT 8.1, 2012 R2, and 10.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/09/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/09/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/09/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2016-2018 Tenable Network Security, Inc.");

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

bulletin = 'MS16-114';
kbs = make_list(
  '3177186',
  '3185611',
  '3185614',
  '3189866'
);

if (get_kb_item("Host/patch_management_checks"))
  hotfix_check_3rd_party(bulletin:bulletin, kbs:make_list(kbs), severity:SECURITY_HOLE);

get_kb_item_or_exit("SMB/Registry/Enumerated");
get_kb_item_or_exit("SMB/WindowsVersion", exit_code:1);

if (hotfix_check_sp_range(vista:'2', win7:'1', win8:'0', win81:'0', win10:'0') <= 0)
  audit(AUDIT_OS_SP_NOT_VULN);

productname = get_kb_item_or_exit("SMB/ProductName", exit_code:1);
if ("Windows 8" >< productname && "8.1" >!< productname)
  audit(AUDIT_OS_SP_NOT_VULN);

share = hotfix_get_systemdrive(as_share:TRUE, exit_on_fail:TRUE);
if (!is_accessible_share(share:share))
  audit(AUDIT_SHARE_FAIL, share);

kb = '3177186';
if (
  # Vista / Windows Server 2008
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"srv.sys", version:"6.0.6002.24000", min_version:"6.0.6002.20000", dir:"\system32\drivers", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"srv.sys", version:"6.0.6002.19673", min_version:"6.0.6002.18000", dir:"\system32\drivers", bulletin:bulletin, kb:kb) ||

  # 7 / Windows Server 2008 R2
  hotfix_is_vulnerable(os:"6.1", sp:1, file:"srv.sys", version:"6.1.7601.23517", min_version:"6.1.7600.20000", dir:"\system32\drivers", bulletin:bulletin, kb:kb) ||

  # 8.1 / Windows Server 2012 R2
  hotfix_is_vulnerable(os:"6.3", sp:0, file:"srv.sys", version:"  6.3.9600.18432", min_version:"6.3.9600.16000", dir:"\system32\drivers", bulletin:bulletin, kb:kb) ||

  # Windows Server 2012
  hotfix_is_vulnerable(os:"6.2", sp:0, file:"srv.sys", version:"6.2.9200.21954", min_version:"6.2.9200.16000", dir:"\system32\drivers", bulletin:bulletin, kb:kb) ||

  # Windows 10
  hotfix_is_vulnerable(os:"10", sp:0, os_build:"14393", file:"srv.sys", version:"10.0.14393.187", dir:"\system32\drivers", bulletin:bulletin, kb:'3189866') ||
  hotfix_is_vulnerable(os:"10", sp:0, os_build:"10586", file:"srv.sys", version:"10.0.10586.589", dir:"\system32\drivers", bulletin:bulletin, kb:'3185614') ||
  hotfix_is_vulnerable(os:"10", sp:0, os_build:"10240", file:"srv.sys", version:"10.0.10240.17113", dir:"\system32\drivers", bulletin:bulletin, kb:'3185611')
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

