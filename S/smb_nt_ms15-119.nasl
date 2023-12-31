#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(86826);
  script_version("1.9");
  script_cvs_date("Date: 2019/11/20");

  script_cve_id("CVE-2015-2478");
  script_bugtraq_id(77478);
  script_xref(name:"MSFT", value:"MS15-119");
  script_xref(name:"MSKB", value:"3092601");
  script_xref(name:"MSKB", value:"3105211");
  script_xref(name:"MSKB", value:"3105213");
  script_xref(name:"IAVA", value:"2015-A-0276");

  script_name(english:"MS15-119: Security Update for Winsock to Address Elevation of Privilege (3104521)");
  script_summary(english:"Checks the version of Afd.sys.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host is affected by an elevation of privilege
vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote Windows host is affected by an elevation of privilege
vulnerability due to a flaw in Winsock in which a call is made to a
memory address without verifying that the address is valid. An
authenticated, remote attacker can exploit this, via a specially
crafted application, to gain elevated privileges on the host.");
  script_set_attribute(attribute:"see_also", value:"https://docs.microsoft.com/en-us/security-updates/SecurityBulletins/2015/ms15-119");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows Vista, 2008, 7,
2008 R2, 8, RT, 2012, 8.1, RT 8.1, 2012 R2, and 10.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2015-2478");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/11/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/11/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/11/10");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2015-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("smb_hotfixes.nasl", "ms_bulletin_checks_possible.nasl");
  script_require_keys("SMB/MS_Bulletin_Checks/Possible");
  script_require_ports(139, 445, "Host/patch_management_checks");

  exit(0);
}

include("audit.inc");
include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");
include("misc_func.inc");

get_kb_item_or_exit('SMB/MS_Bulletin_Checks/Possible');

bulletin = 'MS15-119';

kb = '3092601';

subkbs = make_list(kb, '3105211', '3105213');

if (get_kb_item('Host/patch_management_checks')) hotfix_check_3rd_party(bulletin:bulletin, kbs:subkbs, severity:SECURITY_HOLE);

get_kb_item_or_exit('SMB/Registry/Enumerated');
get_kb_item_or_exit('SMB/WindowsVersion', exit_code:1);

if (hotfix_check_sp_range(vista:'2', win7:'1', win8:'0', win81:'0',  win10:'0') <= 0) audit(AUDIT_OS_SP_NOT_VULN);

share = hotfix_get_systemdrive(exit_on_fail:TRUE, as_share:TRUE);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

if (
  # Windows 10
  hotfix_is_vulnerable(os:"10", sp:0, file:"Afd.sys", version:"10.0.10586.3", min_version:"10.0.10586.0", dir:"\system32\drivers", bulletin:bulletin, kb:"3105211") ||
  hotfix_is_vulnerable(os:"10", sp:0, file:"Afd.sys", version:"10.0.10240.16590", min_version:"10.0.10240.16000", dir:"\system32\drivers", bulletin:bulletin, kb:"3105213") ||

  # Windows 8.1 / Server 2012 R2
  hotfix_is_vulnerable(os:"6.3", sp:0, file:"Afd.sys", version:"6.3.9600.18089", min_version:"6.3.9600.16000", dir:"\system32\drivers", bulletin:bulletin, kb:kb) ||

  # Windows 8 / 2012
  hotfix_is_vulnerable(os:"6.2", sp:0, file:"Afd.sys", version:"6.2.9200.21657", min_version:"6.2.9200.20000", dir:"\system32\drivers", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.2", sp:0, file:"Afd.sys", version:"6.2.9200.17540", min_version:"6.2.9200.16000", dir:"\system32\drivers", bulletin:bulletin, kb:kb) ||

  # Windows 7 / 2008 R2
  hotfix_is_vulnerable(os:"6.1", sp:1, file:"Afd.sys", version:"6.1.7601.23237", min_version:"6.1.7601.22000", dir:"\system32\drivers", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.1", sp:1, file:"Afd.sys", version:"6.1.7601.19031", min_version:"6.1.7600.17000", dir:"\system32\drivers", bulletin:bulletin, kb:kb) ||

  # Windows Vista / 2008
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"Afd.sys", version:"6.0.6002.23823", min_version:"6.0.6002.23000", dir:"\system32\drivers", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"Afd.sys", version:"6.0.6002.19513", min_version:"6.0.6002.18000", dir:"\system32\drivers", bulletin:bulletin, kb:kb)
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
