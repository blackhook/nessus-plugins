#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(31793);
 script_version("1.30");
 script_cvs_date("Date: 2018/11/15 20:50:30");

 script_cve_id("CVE-2008-0087");
 script_bugtraq_id(28553);
 script_xref(name:"MSFT", value:"MS08-020");
 script_xref(name:"MSKB", value:"945553");

 script_name(english:"MS08-020: Vulnerability in DNS Client Could Allow Spoofing (945553)");
 script_summary(english:"Determines the presence of update 945553");

 script_set_attribute(attribute:"synopsis", value:"The remote host is vulnerable to DNS spoofing.");
 script_set_attribute(attribute:"description", value:
"There is a flaw in the remote DNS client that could let an attacker
send malicious DNS responses to DNS requests made by the remote host,
thereby spoofing or redirecting internet traffic from legitimate
locations.");
 script_set_attribute(attribute:"see_also", value:"https://docs.microsoft.com/en-us/security-updates/SecurityBulletins/2008/ms08-020");
 script_set_attribute(attribute:"solution", value:
"Microsoft has released patches for Windows 2000, XP, 2003 Server and
Vista.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");
 script_cwe_id(287);

 script_set_attribute(attribute:"vuln_publication_date", value:"2008/04/08");
 script_set_attribute(attribute:"patch_publication_date", value:"2008/04/08");
 script_set_attribute(attribute:"plugin_publication_date", value:"2008/04/08");

 script_set_attribute(attribute:"plugin_type", value:"local");
 script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);

 script_copyright(english:"This script is Copyright (C) 2008-2018 Tenable Network Security, Inc.");
 script_family(english:"Windows : Microsoft Bulletins");

 script_dependencies("smb_hotfixes.nasl", "ms_bulletin_checks_possible.nasl");
 script_require_keys("SMB/MS_Bulletin_Checks/Possible");
 script_require_ports(139, 445, 'Host/patch_management_checks');
 exit(0);
}

include("audit.inc");
include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");
include("misc_func.inc");

get_kb_item_or_exit("SMB/MS_Bulletin_Checks/Possible");

bulletin = 'MS08-020';
kb = '945553';

kbs = make_list(kb);
if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_WARNING);


get_kb_item_or_exit("SMB/Registry/Enumerated");
get_kb_item_or_exit("SMB/WindowsVersion", exit_code:1);

if (hotfix_check_sp_range(win2k:'4,5', xp:'2', win2003:'1,2', vista:'0') <= 0) audit(AUDIT_OS_SP_NOT_VULN);

rootfile = hotfix_get_systemroot();
if (!rootfile) exit(1, "Failed to get the system root.");

share = hotfix_path2share(path:rootfile);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

if (
  hotfix_is_vulnerable(os:"6.0", sp:0, file:"dnsapi.dll", version:"6.0.6000.16615", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.0", sp:0, file:"dnsapi.dll", version:"6.0.6000.20740", min_version:"6.0.6000.20000", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"5.2", sp:2, file:"dnsapi.dll", version:"5.2.3790.4238", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"5.2", sp:1, file:"dnsapi.dll", version:"5.2.3790.3092", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"5.1", sp:2, file:"dnsapi.dll", version:"5.1.2600.3316", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"5.0", file:"dnsapi.dll", version:"5.0.2195.7151", dir:"\system32", bulletin:bulletin, kb:kb)
)
{
  set_kb_item(name:"SMB/Missing/"+bulletin, value:TRUE);
  hotfix_security_warning();
  hotfix_check_fversion_end();
  exit(0);
}
else
{
  hotfix_check_fversion_end();
  audit(AUDIT_HOST_NOT, 'affected');
}
