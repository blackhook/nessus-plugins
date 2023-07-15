#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(82776);
  script_version("1.11");
  script_cvs_date("Date: 2019/11/22");

  script_cve_id("CVE-2015-1638");
  script_bugtraq_id(74002);
  script_xref(name:"MSFT", value:"MS15-040");
  script_xref(name:"MSKB", value:"3045711");

  script_name(english:"MS15-040: Vulnerability in Active Directory Federation Services Could Allow Information Disclosure (3045711)");
  script_summary(english:"Checks the version of a DLL file.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host is affected by an information disclosure
vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote Windows host is affected by an information disclosure
vulnerability in Active Directory Federation Services (AD FS) due to a
failure to properly log off a user. A local attacker, by reopening an
application from which a user has logged off, can exploit this to
obtain user information to which the AD FS server has access.");
  script_set_attribute(attribute:"see_also", value:"https://docs.microsoft.com/en-us/security-updates/SecurityBulletins/2015/ms15-040");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows Server 2012 R2");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2015-1638");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/04/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/04/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/04/14");

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
include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");
include("misc_func.inc");

get_kb_item_or_exit("SMB/MS_Bulletin_Checks/Possible");

bulletin = 'MS15-040';
kbs = make_list('3045711');

if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_WARNING);

get_kb_item_or_exit("SMB/Registry/Enumerated");
get_kb_item_or_exit("SMB/WindowsVersion", exit_code:1);
productname = get_kb_item_or_exit("SMB/ProductName", exit_code:1);

if (hotfix_check_sp_range(win81:'0') <= 0) audit(AUDIT_OS_SP_NOT_VULN);
if ("Server 2012 R2" >!< productname) audit(AUDIT_OS_SP_NOT_VULN);

share = hotfix_get_systemdrive(as_share:TRUE, exit_on_fail:TRUE);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

# Server 2012 R2 (KB3045711)
if (
  hotfix_is_vulnerable(os:"6.3", sp:0, file:"microsoft.identityserver.diagnostics.dll", version:"6.3.9600.17720", min_version:"6.3.9600.16000", dir:"\Microsoft.NET\assembly\GAC_MSIL\Microsoft.IdentityServer.Diagnostics\v4.0_6.3.0.0__31bf3856ad364e35", bulletin:bulletin, kb:"3045711")
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
