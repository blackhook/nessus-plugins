#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(90440);
  script_version("1.9");
  script_cvs_date("Date: 2019/11/20");

  script_cve_id("CVE-2016-0128");
  script_bugtraq_id(86002);
  script_xref(name:"MSFT", value:"MS16-047");
  script_xref(name:"MSKB", value:"3148527");
  script_xref(name:"MSKB", value:"3149090");
  script_xref(name:"MSKB", value:"3147461");
  script_xref(name:"MSKB", value:"3147458");
  script_xref(name:"CERT", value:"813296");
  script_xref(name:"IAVA", value:"2016-A-0093");

  script_name(english:"MS16-047: Security Update for SAM and LSAD Remote Protocols (3148527) (Badlock)");
  script_summary(english:"Checks the version of lsasrv.dll and kerberos.dll.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host is affected by an elevation of privilege
vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote Windows host is affected by an elevation of privilege
vulnerability in the Security Account Manager (SAM) and Local Security
Authority (Domain Policy) (LSAD) protocols due to improper
authentication level negotiation over Remote Procedure Call (RPC)
channels. A man-in-the-middle attacker able to intercept
communications between a client and a server hosting a SAM database
can exploit this to force the authentication level to downgrade,
allowing the attacker to impersonate an authenticated user and access
the SAM database.");
  script_set_attribute(attribute:"see_also", value:"https://docs.microsoft.com/en-us/security-updates/SecurityBulletins/2016/ms16-047");
  script_set_attribute(attribute:"see_also", value:"http://badlock.org/");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows Vista, 2008, 7,
2008 R2, 2012, 8.1, RT 8.1, 2012 R2, and 10.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2016-0128");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"in_the_news", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/03/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/04/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/04/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_set_attribute(attribute:"stig_severity", value:"I");
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

bulletin = 'MS16-047';
kb  = "3148527";

kbs = make_list(kb, "3149090", "3147461", "3147458");
if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_WARNING);

get_kb_item_or_exit("SMB/Registry/Enumerated");
get_kb_item_or_exit("SMB/WindowsVersion", exit_code:1);
productname = get_kb_item_or_exit("SMB/ProductName", exit_code:1);

if (hotfix_check_sp_range(vista:'2', win7:'1', win8:'0', win81:'0', win10:'0') <= 0) audit(AUDIT_OS_SP_NOT_VULN);
if ("Windows 8" >< productname && "Windows 8.1" >!< productname) audit(AUDIT_OS_SP_NOT_VULN);

share = hotfix_get_systemdrive(as_share:TRUE, exit_on_fail:TRUE);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

if (
  # Windows 8.1 / Windows Server 2012 R2
  hotfix_is_vulnerable(os:"6.3",  sp:0, file:"lsasrv.dll", version:"6.3.9600.18267", min_version:"6.3.9600.16000", dir:"\system32", bulletin:bulletin, kb:"3149090") ||

  # Windows Server 2012
  hotfix_is_vulnerable(os:"6.2",  sp:0, file:"kerberos.dll", version:"6.2.9200.21811", min_version:"6.2.9200.16000", dir:"\system32", bulletin:bulletin, kb:"3149090") ||

  # Windows 7 / Server 2008 R2
  hotfix_is_vulnerable(os:"6.1",  sp:1, file:"lsasrv.dll", version:"6.1.7601.23390", min_version:"6.1.7601.20000", dir:"\system32", bulletin:bulletin, kb:"3149090") ||
  hotfix_is_vulnerable(os:"6.1",  sp:1, file:"lsasrv.dll", version:"6.1.7601.19623", min_version:"6.1.7600.16000", dir:"\system32", bulletin:bulletin, kb:"3149090") ||

  # Vista / Windows Server 2008
  hotfix_is_vulnerable(os:"6.0",  sp:2, file:"lsasrv.dll", version:"6.0.6002.23936", min_version:"6.0.6002.20000", dir:"\system32", bulletin:bulletin, kb:"3149090") ||
  hotfix_is_vulnerable(os:"6.0",  sp:2, file:"lsasrv.dll", version:"6.0.6002.19623", min_version:"6.0.6001.18000", dir:"\system32", bulletin:bulletin, kb:"3149090") ||

  # Windows 10 Check
  hotfix_is_vulnerable(os:"10", sp:0, file:"lsasrv.dll", version:"10.0.10586.212",   min_version:"10.0.10586.0",     dir:"\system32", bulletin:bulletin, kb:"3147458") ||
  hotfix_is_vulnerable(os:"10", sp:0, file:"lsasrv.dll", version:"10.0.10240.16766", min_version:"10.0.10240.16000", dir:"\system32", bulletin:bulletin, kb:"3147461")
)
{
  set_kb_item(name:'SMB/Missing/'+bulletin, value:TRUE);
  hotfix_security_warning();
  hotfix_check_fversion_end();
  exit(0);
}
else
{
  hotfix_check_fversion_end();
  audit(AUDIT_HOST_NOT, 'affected');
}
