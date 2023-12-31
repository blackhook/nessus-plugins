#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(85322);
  script_version("1.8");
  script_cvs_date("Date: 2019/11/22");

  script_cve_id("CVE-2015-2428", "CVE-2015-2429", "CVE-2015-2430");
  script_bugtraq_id(76227, 76231, 76233);
  script_xref(name:"MSFT", value:"MS15-090");
  script_xref(name:"MSKB", value:"3060716");
  script_xref(name:"IAVA", value:"2015-A-0193");

  script_name(english:"MS15-090: Vulnerabilities in Microsoft Windows Could Allow Elevation of Privilege (3060716)");
  script_summary(english:"Checks the file version of ntdll.dll.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host is affected by multiple elevation of privilege
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote Windows host is affected by multiple elevation of privilege
vulnerabilities in Windows Object Manager :

  - A flaw exists in Windows Object Manager due to a failure
    to properly validate and enforce impersonation levels. A
    remote, authenticated attacker can exploit this
    vulnerability, via a specially crafted application, to
    bypass impersonation-level security, resulting in a
    privilege escalation. (CVE-2015-2428)

  - A flaw exists in Windows Object Manager due to a failure
    to properly restrict certain registry interactions from
    within vulnerable sandboxed applications. A remote
    attacker can exploit this vulnerability by convincing a
    user to open specially crafted file that invokes a
    vulnerable sandboxed application, to interact with the
    registry and escape the application sandbox, resulting
    in a privilege escalation. (CVE-2015-2429)

  - A flaw exists in Windows Object Manager due to a failure
    to properly restrict certain filesystem interactions
    from within vulnerable sandboxed applications. A remote
    attacker can exploit this vulnerability by convincing a
    user to open a specially crafted file that invokes a
    vulnerable sandboxed application, to interact with the
    filesystem and escape the application sandbox, resulting
    in a privilege escalation. (CVE-2015-2430)");
  script_set_attribute(attribute:"see_also", value:"https://docs.microsoft.com/en-us/security-updates/SecurityBulletins/2015/ms15-090");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows Vista, 2008, 7,
2008 R2, 8, RT, 2012, 8.1, RT 8.1, and 2012 R2.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2015-2430");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/08/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/08/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/08/11");

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
include("smb_hotfixes_fcheck.inc");
include("smb_hotfixes.inc");
include("smb_func.inc");
include("misc_func.inc");

get_kb_item_or_exit("SMB/MS_Bulletin_Checks/Possible");

bulletin = 'MS15-090';
kb = '3060716';

kbs = make_list(kb);
if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

get_kb_item_or_exit("SMB/Registry/Enumerated");
get_kb_item_or_exit("SMB/WindowsVersion", exit_code:1);

if (hotfix_check_sp_range(vista:'2', win7:'1', win8:'0', win81:'0') <= 0) audit(AUDIT_OS_SP_NOT_VULN);

share = hotfix_get_systemdrive(as_share:TRUE, exit_on_fail:TRUE);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

if (
  # Windows 8.1 / Windows Server 2012 R2
  hotfix_is_vulnerable(os:"6.3", sp:0, file:"ntdll.dll", version:"6.3.9600.17933", min_version:"6.3.9600.16000", dir:"\system32", bulletin:bulletin, kb:kb) ||

  # Windows 8 / Windows Server 2012
  hotfix_is_vulnerable(os:"6.2", sp:0, file:"ntdll.dll", version:"6.2.9200.21548", min_version:"6.2.9200.20000", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.2", sp:0, file:"ntdll.dll", version:"6.2.9200.17438", min_version:"6.2.9200.16000", dir:"\system32", bulletin:bulletin, kb:kb) ||

  # Windows 7 / Server 2008 R2
  hotfix_is_vulnerable(os:"6.1", sp:1, file:"ntdll.dll", version:"6.1.7601.23126", min_version:"6.1.7601.22000", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.1", sp:1, file:"ntdll.dll", version:"6.1.7601.18923", min_version:"6.1.7600.16000", dir:"\system32", bulletin:bulletin, kb:kb) ||

  # Vista / Windows Server 2008
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"ntdll.dll", version:"6.0.6002.23761", min_version:"6.0.6002.23000", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"ntdll.dll", version:"6.0.6002.19453", min_version:"6.0.6001.18000", dir:"\system32", bulletin:bulletin, kb:kb)
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
