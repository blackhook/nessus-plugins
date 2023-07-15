#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(90432);
  script_version("1.12");
  script_cvs_date("Date: 2019/11/20");

  script_cve_id(
    "CVE-2016-0154",
    "CVE-2016-0155",
    "CVE-2016-0156",
    "CVE-2016-0157",
    "CVE-2016-0158",
    "CVE-2016-0161"
  );
  script_bugtraq_id(
    85894,
    85898,
    85902,
    85904,
    85905,
    85938
  );
  script_xref(name:"MSFT", value:"MS16-038");
  script_xref(name:"MSKB", value:"3147458");
  script_xref(name:"MSKB", value:"3147461");

  script_name(english:"MS16-038: Cumulative Security Update for Microsoft Edge (3148532)");
  script_summary(english:"Checks the file version of edgehtml.dll.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has a web browser installed that is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Microsoft Edge installed on the remote host is missing
Cumulative Security Update 3148532. It is, therefore, affected by
multiple vulnerabilities :

  - Multiple remote code execution vulnerabilities exist due
    to improper handling of objects in memory. An attacker
    can exploit these vulnerabilities by convincing a user
    to visit a specially crafted website, resulting in the
    execution of arbitrary code in the context of the
    current user. (CVE-2016-0154, CVE-2016-0155,
    CVE-2016-0156, CVE-2016-0157)

  - A privilege escalation vulnerability exists due to
    improper enforcement of cross-domain policies. An
    attacker can exploit this vulnerability by convincing a
    user to visit a specially crafted website, allowing
    the attacker to inject information from an outside
    domain. (CVE-2016-0158)

  - A privilege escalation vulnerability exists due to
    improper validation of JavaScript. An attacker can
    exploit this, by convincing a user to visit a specially
    crafted website, to run JavaScript at a higher privilege
    level than is allowed. (CVE-2016-0161)

Note that CVE-2016-0155 will only affect Windows client installations
running at the version 1511 level.");
  script_set_attribute(attribute:"see_also", value:"https://docs.microsoft.com/en-us/security-updates/SecurityBulletins/2016/ms16-038");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows 10.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2016-0157");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/04/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/04/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/04/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:edge");
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
include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");
include("smb_reg_query.inc");
include("misc_func.inc");

get_kb_item_or_exit('SMB/MS_Bulletin_Checks/Possible');

bulletin = 'MS16-038';
kbs = make_list('3147458', '3147461');

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
  hotfix_is_vulnerable(os:"10", sp:0, file:"edgehtml.dll", version:"11.0.10586.212", min_version:"11.0.10586.0", dir:"\system32", bulletin:bulletin, kb:"3147458") ||
  hotfix_is_vulnerable(os:"10", sp:0, file:"edgehtml.dll", version:"11.0.10240.16766", dir:"\system32", bulletin:bulletin, kb:"3147461")
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
