#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(86820);
  script_version("1.10");
  script_cvs_date("Date: 2018/11/15 20:50:31");

  script_cve_id(
    "CVE-2015-6064",
    "CVE-2015-6073",
    "CVE-2015-6078",
    "CVE-2015-6088"
  );
  script_bugtraq_id(
    77470,
    77468,
    77467,
    77469
  );
  script_xref(name:"MSFT", value:"MS15-113");
  script_xref(name:"MSKB", value:"3105211");
  script_xref(name:"MSKB", value:"3105213");

  script_name(english:"MS15-113: Cumulative Security Update for Microsoft Edge (3104519)");
  script_summary(english:"Checks the file version of edgehtml.dll.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has a web browser installed that is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Microsoft Edge installed on the remote Windows host is
missing Cumulative Security Update 3104519. It is, therefore, affected
by multiple vulnerabilities :

  - Multiple remote code execution vulnerabilities exist due
    to improper handling of objects in memory. A remote
    attacker can exploit these vulnerabilities, via a
    specially crafted website, to execute arbitrary code in
    the context of the current user. (CVE-2015-6064,
    CVE-2015-6073, CVE-2015-6078)

  - A security feature bypass vulnerability exists due to
    a failure to use Address Space Layout Randomization
    (ASLR). An attacker can exploit this to predict memory
    offsets in a call stack. (CVE-2015-6088)");
  script_set_attribute(attribute:"see_also", value:"https://docs.microsoft.com/en-us/security-updates/SecurityBulletins/2015/ms15-113");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows 10.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/11/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/11/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/11/10");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:edge");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2015-2018 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl", "ms_bulletin_checks_possible.nasl");
  script_require_keys("SMB/MS_Bulletin_Checks/Possible");
  script_require_ports(139, 445, "Host/patch_management_checks");

  exit(0);
}

include("audit.inc");
include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");
include("smb_reg_query.inc");
include("misc_func.inc");

get_kb_item_or_exit('SMB/MS_Bulletin_Checks/Possible');

bulletin = 'MS15-113';
kbs = make_list('3105211', '3105213'); # Cumulative update for Windows 10: November 10, 2015

if (get_kb_item('Host/patch_management_checks')) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

get_kb_item_or_exit("SMB/Registry/Enumerated");
get_kb_item_or_exit('SMB/WindowsVersion', exit_code:1);

# Server core is not affected
if (hotfix_check_server_core() == 1) audit(AUDIT_WIN_SERVER_CORE);

if (hotfix_check_sp_range(win10:'0') <= 0) audit(AUDIT_OS_SP_NOT_VULN);

share = hotfix_get_systemdrive(exit_on_fail:TRUE, as_share:TRUE);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

if (
  # Windows 10
  hotfix_is_vulnerable(os:"10", sp:0, file:"edgehtml.dll", version:"11.0.10586.3", min_version:"11.0.10586.0", dir:"\system32", bulletin:bulletin, kb:"3105211") ||
  hotfix_is_vulnerable(os:"10", sp:0, file:"edgehtml.dll", version:"11.0.10240.16590", dir:"\system32", bulletin:bulletin, kb:"3105213")
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
