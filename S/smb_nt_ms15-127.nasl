#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(87256);
  script_version("1.7");
  script_cvs_date("Date: 2019/11/20");

  script_cve_id("CVE-2015-6125");
  script_bugtraq_id(78496);
  script_xref(name:"MSFT", value:"MS15-127");
  script_xref(name:"MSKB", value:"3100465");
  script_xref(name:"IAVA", value:"2015-A-0302");

  script_name(english:"MS15-127: Security Update for Microsoft Windows DNS to Address Remote Code Execution (3100465)");
  script_summary(english:"Checks the version of dns.exe.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by a remote code execution vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote Windows host is affected by a remote code execution
vulnerability in the Windows Domain Name System (DNS) server due to
improper parsing of DNS requests. A remote attacker can exploit this,
via specially crafted DNS requests, to execute arbitrary code in the
context of the Local System Account.");
  script_set_attribute(attribute:"see_also", value:"https://docs.microsoft.com/en-us/security-updates/SecurityBulletins/2015/ms15-127");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows 2008, 2008 R2,
2012, and 2012 R2.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2015-6125");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/12/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/12/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/12/08");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_set_attribute(attribute:"stig_severity", value:"I");
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
include("smb_hotfixes_fcheck.inc");
include("smb_hotfixes.inc");
include("smb_func.inc");
include("misc_func.inc");

get_kb_item_or_exit("SMB/MS_Bulletin_Checks/Possible");

bulletin = 'MS15-127';
kb  = '3100465';
kbs = make_list(kb);

if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

get_kb_item_or_exit("SMB/Registry/Enumerated");
get_kb_item_or_exit("SMB/WindowsVersion", exit_code:1);

if (hotfix_check_sp_range(vista:'2', win7:'1', win8:'0', win81:'0') <= 0)
  audit(AUDIT_OS_SP_NOT_VULN);

share = hotfix_get_systemdrive(as_share:TRUE, exit_on_fail:TRUE);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

# Vista, Windows 7, Windows 8, and Windows 8.1 are not affected
productname = get_kb_item_or_exit("SMB/ProductName", exit_code:1);
if ("Vista" >< productname || "Windows 7" >< productname || "Windows 8" >< productname)
  exit(0, "The host is running "+productname+" and hence is not affected.");

if (
  # Windows Server 2012 R2
  hotfix_is_vulnerable(os:"6.3", sp:0, file:"dns.exe", version:"6.3.9600.18094",  min_version:"6.3.9600.17000", dir:"\system32", bulletin:bulletin, kb:kb) ||

  # Windows Server 2012
  hotfix_is_vulnerable(os:"6.2", sp:0, file:"dns.exe", version:"6.2.9200.21685", min_version:"6.2.9200.20000", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.2", sp:0, file:"dns.exe", version:"6.2.9200.17568", min_version:"6.2.9200.16000", dir:"\system32", bulletin:bulletin, kb:kb) ||

  # Windows Server 2008 R2
  hotfix_is_vulnerable(os:"6.1", sp:1, file:"dns.exe", version:"6.1.7601.23251", min_version:"6.1.7601.23000", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.1", sp:1, file:"dns.exe", version:"6.1.7601.19046", min_version:"6.1.7600.18000", dir:"\system32", bulletin:bulletin, kb:kb) ||

  # Windows Server 2008
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"dns.exe", version:"6.0.6002.23836", min_version:"6.0.6002.23000", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"dns.exe", version:"6.0.6002.19526", min_version:"6.0.6002.16000", dir:"\system32", bulletin:bulletin, kb:kb)
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
