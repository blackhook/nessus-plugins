#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(91597);
  script_version("1.12");
  script_cvs_date("Date: 2019/11/19");

  script_cve_id(
    "CVE-2016-3198",
    "CVE-2016-3199",
    "CVE-2016-3201",
    "CVE-2016-3202",
    "CVE-2016-3203",
    "CVE-2016-3214",
    "CVE-2016-3215",
    "CVE-2016-3222"
  );
  script_bugtraq_id(
    91086,
    91087,
    91090,
    91092,
    91093,
    91094,
    91112
  );
  script_xref(name:"MSFT", value:"MS16-068");
  script_xref(name:"MSKB", value:"3163017");
  script_xref(name:"MSKB", value:"3163018");

  script_name(english:"MS16-068: Cumulative Security Update for Microsoft Edge (3163656)");
  script_summary(english:"Checks the file version of edgehtml.dll.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has a web browser installed that is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Microsoft Edge installed on the remote Windows host is
missing Cumulative Security Update 3163656. It is, therefore, affected
by multiple vulnerabilities :

  - A security feature bypass vulnerability exists due to a
    failure to properly validate specially crafted
    documents. An unauthenticated, remote attacker can
    exploit this vulnerability by convincing a user to load
    a page or visit a website containing malicious content,
    allowing the attacker to bypass the Edge Content
    Security Policy (CSP). (CVE-2016-3198)

  - Multiple remote code execution vulnerabilities exist in
    the Chakra JavaScript engine due to improper handling of
    objects in memory. An unauthenticated, remote attacker
    can exploit these vulnerabilities by convincing a user
    to visit a specially crafted website or open a specially
    crafted Microsoft Office document that hosts the Edge
    rendering engine, resulting in the execution of
    arbitrary code in the context of the current user.
    (CVE-2016-3199, CVE-2016-3202, CVE-2016-3214,
    CVE-2016-3222)

  - Multiple information disclosure vulnerabilities exist
    due to improper parsing of .pdf files. An
    unauthenticated, remote attacker can exploit these
    vulnerabilities by convincing a user to open a specially
    crafted .pdf file, resulting in the disclosure of
    sensitive information in the context of the current
    user. (CVE-2016-3201, CVE-2016-3215)

  - A remote code execution vulnerability exists due to
    improper parsing of .pdf files. An unauthenticated,
    remote attacker can exploit this vulnerability by
    convincing a user to open a specially crafted .pdf file,
    resulting in the execution of arbitrary code in the
    context of the current user. (CVE-2016-3203)

Note that CVE-2016-3214, CVE-2016-3215, and CVE-2016-3222 only affect
Windows 10 version 1511.");
  script_set_attribute(attribute:"see_also", value:"https://docs.microsoft.com/en-us/security-updates/SecurityBulletins/2016/ms16-068");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows 10.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2016-3222");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/06/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/06/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/06/14");

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

bulletin = 'MS16-068';
kbs = make_list('3163018', '3163017');

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
  hotfix_is_vulnerable(os:"10", sp:0, file:"edgehtml.dll", version:"11.0.10586.420", min_version:"11.0.10586.0", dir:"\system32", bulletin:bulletin, kb:"3163018") ||
  hotfix_is_vulnerable(os:"10", sp:0, file:"edgehtml.dll", version:"11.0.10240.16942", dir:"\system32", bulletin:bulletin, kb:"3163017")
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
