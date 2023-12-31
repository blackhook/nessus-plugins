#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(62464);
  script_version("1.10");
  script_cvs_date("Date: 2019/12/04");

  script_cve_id("CVE-2012-2551");
  script_bugtraq_id(55778);
  script_xref(name:"MSFT", value:"MS12-069");
  script_xref(name:"IAVB", value:"2012-B-0103");
  script_xref(name:"MSKB", value:"2743555");

  script_name(english:"MS12-069: Vulnerability in Kerberos Could Allow Denial of Service (2743555)");
  script_summary(english:"Checks version of kerberos.dll");

  script_set_attribute(attribute:"synopsis", value:
"The remote implementation of Kerberos is affected by a denial of
service vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote Windows host is affected by a vulnerability that could
result in a denial of service if a remote attacker sends a specially
crafted session request to the Kerberos server.");
  script_set_attribute(attribute:"see_also", value:"https://docs.microsoft.com/en-us/security-updates/SecurityBulletins/2012/ms12-069");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows 7 and 2008 R2.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2012-2551");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/10/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/10/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/10/10");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2012-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

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

bulletin = 'MS12-069';
kb = '2743555';
kbs = make_list(kb);

if (get_kb_item('Host/patch_management_checks'))
  hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_WARNING);

get_kb_item_or_exit("SMB/Registry/Enumerated");
get_kb_item_or_exit('SMB/WindowsVersion', exit_code:1);

if (hotfix_check_sp_range(win7:'0,1') <= 0)
  audit(AUDIT_OS_SP_NOT_VULN);

rootfile = hotfix_get_systemroot();
if (!rootfile) exit(1, "Failed to get the system root.");

share = hotfix_path2share(path:rootfile);
if (!is_accessible_share(share:share))
  audit(AUDIT_SHARE_FAIL, share);

if (
  # Windows 7 / 2008 R2
  hotfix_is_vulnerable(os:"6.1", sp:1, file:"kerberos.dll", version:"6.1.7601.22084", min_version:"6.1.7601.21000", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.1", sp:1, file:"kerberos.dll", version:"6.1.7601.17926", min_version:"6.1.7601.17000", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.1", sp:0, file:"kerberos.dll", version:"6.1.7600.21298", min_version:"6.1.7600.20000", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.1", sp:0, file:"kerberos.dll", version:"6.1.7600.17095", min_version:"6.1.7600.16000", dir:"\system32", bulletin:bulletin, kb:kb)
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
