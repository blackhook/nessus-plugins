#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(86372);
  script_version("1.11");
  script_cvs_date("Date: 2019/11/20");

  script_cve_id("CVE-2015-6057", "CVE-2015-6058");
  script_bugtraq_id(76980, 76990);
  script_xref(name:"MSFT", value:"MS15-107");
  script_xref(name:"MSKB", value:"3096448");

  script_name(english:"MS15-107: Cumulative Security Update for Microsoft Edge (3096448)");
  script_summary(english:"Checks the file version of edgehtml.dll.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has a web browser installed that is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Microsoft Edge installed on the remote Windows host is
missing Cumulative Security Update 3096448. It is, therefore, affected
by multiple vulnerabilities :

  - An information disclosure vulnerability exists due to
    improper handling of objects in memory. A remote
    attacker can exploit this, via a specially crafted
    website, to disclose arbitrary memory content.
    (CVE-2015-6057)

  - A cross-site scripting filter bypass vulnerability
    exists due to improper disabling of an HTML attribute in
    otherwise appropriately filtered HTTP response data. A
    remote attacker can exploit this vulnerability by
    convincing a user to visit a website containing
    specially crafted content, resulting in the execution of
    arbitrary script code in the wrong security context.
    (CVE-2015-6058)");
  script_set_attribute(attribute:"see_also", value:"https://docs.microsoft.com/en-us/security-updates/SecurityBulletins/2015/ms15-107");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows 10.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2015-6057");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/10/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/10/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/10/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:edge");
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
include("smb_reg_query.inc");
include("misc_func.inc");

get_kb_item_or_exit('SMB/MS_Bulletin_Checks/Possible');

bulletin = 'MS15-107';
kb = '3096448'; # Cumulative update for Windows 10: October 13, 2015

kbs = make_list(kb);
if (get_kb_item('Host/patch_management_checks')) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_WARNING);

get_kb_item_or_exit("SMB/Registry/Enumerated");
get_kb_item_or_exit('SMB/WindowsVersion', exit_code:1);

# Server core is not affected
if (hotfix_check_server_core() == 1) audit(AUDIT_WIN_SERVER_CORE);

if (hotfix_check_sp_range(win10:'0') <= 0) audit(AUDIT_OS_SP_NOT_VULN);

share = hotfix_get_systemdrive(exit_on_fail:TRUE, as_share:TRUE);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

if (
  # Windows 10
  hotfix_is_vulnerable(os:"10", sp:0, file:"edgehtml.dll", version:"11.0.10240.16549", dir:"\system32", bulletin:bulletin, kb:kb)
)
{
  set_kb_item(name:"www/0/XSS", value:TRUE);
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
