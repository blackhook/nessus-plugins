#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(81745);
  script_version("1.12");
  script_cvs_date("Date: 2019/11/22");

  script_cve_id("CVE-2015-1637");
  script_bugtraq_id(72965);
  script_xref(name:"CERT", value:"243585");
  script_xref(name:"MSFT", value:"MS15-031");
  script_xref(name:"MSKB", value:"3046049");

  script_name(english:"MS15-031: Vulnerability in Schannel Could Allow Security Feature Bypass (3046049) (FREAK)");
  script_summary(english:"Checks the version of schannel.dll.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host is affected by a security feature bypass
vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote Windows host is affected by a security feature bypass
vulnerability, known as FREAK (Factoring attack on RSA-EXPORT Keys),
due to the support of weak EXPORT_RSA cipher suites with keys less
than or equal to 512 bits. A man-in-the-middle attacker may be able to
downgrade the SSL/TLS connection to use EXPORT_RSA cipher suites which
can be factored in a short amount of time, allowing the attacker to
intercept and decrypt the traffic.");
  script_set_attribute(attribute:"see_also", value:"https://docs.microsoft.com/en-us/security-updates/SecurityBulletins/2015/ms15-031");
  script_set_attribute(attribute:"see_also", value:"https://www.smacktls.com/#freak");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows 2003, Vista, 2008,
7, 2008 R2, 8, 2012, 8.1, and 2012 R2.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2015-1637");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"in_the_news", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/03/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/03/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/03/10");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
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

bulletin = 'MS15-031';

kb = "3046049";
kbs = make_list(
  kb
);
if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_WARNING);

get_kb_item_or_exit("SMB/Registry/Enumerated");
get_kb_item_or_exit("SMB/WindowsVersion", exit_code:1);

if (hotfix_check_sp_range(win2003:'2', vista:'2', win7:'1', win8:'0', win81:'0') <= 0) audit(AUDIT_OS_SP_NOT_VULN);

share = hotfix_get_systemdrive(exit_on_fail:TRUE, as_share:TRUE);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

# The 2k3 checks could flag XP 64, which is unsupported
productname = get_kb_item_or_exit("SMB/ProductName", exit_code:1);
if ("Windows XP" >< productname) audit(AUDIT_OS_SP_NOT_VULN);

if (
  # Windows 8.1 / 2012 R2
  hotfix_is_vulnerable(os:"6.3", file:"schannel.dll", version:"6.3.9600.17702", min_version:"6.3.9600.16000", dir:"\system32", bulletin:bulletin, kb:kb) ||

  # Windows 8 / 2012
  hotfix_is_vulnerable(os:"6.2", file:"schannel.dll", version:"6.2.9200.21410", min_version:"6.2.9200.20000", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.2", file:"schannel.dll", version:"6.2.9200.17293", min_version:"6.2.9200.16000", dir:"\system32", bulletin:bulletin, kb:kb) ||

  # Windows 7 / 2008 R2
  hotfix_is_vulnerable(os:"6.1", sp:1, file:"schannel.dll", version:"6.1.7601.22983", min_version:"6.1.7601.22000", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.1", sp:1, file:"schannel.dll", version:"6.1.7601.18779", min_version:"6.1.7600.18000", dir:"\system32", bulletin:bulletin, kb:kb) ||

  # Vista / 2008
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"schannel.dll", version:"6.0.6002.23640", min_version:"6.0.6002.23000", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"schannel.dll", version:"6.0.6002.19332", min_version:"6.0.6002.18000", dir:"\system32", bulletin:bulletin, kb:kb) ||

  # Windows 2003
  hotfix_is_vulnerable(os:"5.2", sp:2, file:"schannel.dll", version:"5.2.3790.5564", dir:"\system32", bulletin:bulletin, kb:kb)

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
