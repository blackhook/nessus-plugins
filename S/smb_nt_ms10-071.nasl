#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(49948);
  script_version("1.21");
  script_cvs_date("Date: 2018/11/15 20:50:30");

  script_cve_id(
    "CVE-2010-0808",
    "CVE-2010-3243",
    "CVE-2010-3324",
    "CVE-2010-3325",
    "CVE-2010-3326",
    "CVE-2010-3327",
    "CVE-2010-3328",
    "CVE-2010-3329",
    "CVE-2010-3330",
    "CVE-2010-3331"
  );
  script_bugtraq_id(
    42993,
    42467,
    43695,
    43696,
    43703,
    43704,
    43705,
    43706,
    43707,
    43709
  );
  script_xref(name:"MSFT", value:"MS10-071");
  script_xref(name:"MSKB", value:"2360131");

  script_name(english:"MS10-071: Cumulative Security Update for Internet Explorer (2360131)");
  script_summary(english:"Checks version of Mshtml.dll");

  script_set_attribute(attribute:"synopsis", value:
"Arbitrary code can be executed on the remote host through a web
browser.");

  script_set_attribute(attribute:"description", value:
"The remote host is missing IE Security Update 2360131.

The remote version of IE is affected by several vulnerabilities that
may allow an attacker to execute arbitrary code on the remote host.");

  script_set_attribute(attribute:"see_also", value:"https://docs.microsoft.com/en-us/security-updates/SecurityBulletins/2010/ms10-071");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for XP, 2003, Vista, 2008, 7,
and 2008 R2.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/08/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/10/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/10/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2010-2018 Tenable Network Security, Inc.");

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

bulletin = 'MS10-071';
kbs = make_list("2360131");
if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

get_kb_item_or_exit("SMB/Registry/Enumerated");
get_kb_item_or_exit("SMB/WindowsVersion", exit_code:1);

if (hotfix_check_sp_range(xp:'3', win2003:'2', vista:'1,2', win7:'0') <= 0) audit(AUDIT_OS_SP_NOT_VULN);
if (hotfix_check_server_core() == 1) audit(AUDIT_WIN_SERVER_CORE);

rootfile = hotfix_get_systemroot();
if (!rootfile) exit(1, "Failed to get the system root.");

share = hotfix_path2share(path:rootfile);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

kb = "2360131";
if (
  # Windows 7 and Windows Server 2008 R2
  #
  # - Internet Explorer 8
  hotfix_is_vulnerable(os:"6.1",       file:"Mshtml.dll", version:"8.0.7600.20795", min_version:"8.0.7600.20000", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.1",       file:"Mshtml.dll", version:"8.0.7600.16671", min_version:"8.0.7600.16000", dir:"\system32", bulletin:bulletin, kb:kb) ||

  # Vista / Windows 2008
  #
  # - Internet Explorer 8
  hotfix_is_vulnerable(os:"6.0",       file:"Mshtml.dll", version:"8.0.6001.23067", min_version:"8.0.6001.20000", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.0",       file:"Mshtml.dll", version:"8.0.6001.18975", min_version:"8.0.6001.18000", dir:"\system32", bulletin:bulletin, kb:kb) ||
  # - Internet Explorer 7
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"Mshtml.dll", version:"7.0.6002.22477", min_version:"7.0.6002.20000", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"Mshtml.dll", version:"7.0.6002.18304", min_version:"7.0.6002.18000", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.0", sp:1, file:"Mshtml.dll", version:"7.0.6001.22753", min_version:"7.0.6001.20000", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.0", sp:1, file:"Mshtml.dll", version:"7.0.6001.18522", min_version:"7.0.6001.18000", dir:"\system32", bulletin:bulletin, kb:kb) ||

  # Windows 2003 / XP 64-bit
  #
  # - Internet Explorer 8
  hotfix_is_vulnerable(os:"5.2", sp:2, file:"Mshtml.dll", version:"8.0.6001.18972", min_version:"8.0.0.0", dir:"\system32", bulletin:bulletin, kb:kb) ||
  # - Internet Explorer 7
  hotfix_is_vulnerable(os:"5.2", sp:2, file:"Mshtml.dll", version:"7.0.6000.17091", min_version:"7.0.0.0", dir:"\system32", bulletin:bulletin, kb:kb) ||
  # - Internet Explorer 6
  hotfix_is_vulnerable(os:"5.2", sp:2, file:"Mshtml.dll", version:"6.0.3790.4772",  min_version:"6.0.0.0", dir:"\system32", bulletin:bulletin, kb:kb) ||

  # Windows XP x86
  #
  # - Internet Explorer 8
  hotfix_is_vulnerable(os:"5.1", sp:3, file:"Mshtml.dll", version:"8.0.6001.18972", min_version:"8.0.0.0", dir:"\system32", bulletin:bulletin, kb:kb) ||
  # - Internet Explorer 7
  hotfix_is_vulnerable(os:"5.1", sp:3, file:"Mshtml.dll", version:"7.0.6000.17091", min_version:"7.0.0.0", dir:"\system32", bulletin:bulletin, kb:kb) ||
  # - Internet Explorer 6
  hotfix_is_vulnerable(os:"5.1", sp:3, file:"Mshtml.dll", version:"6.0.2900.6036",  min_version:"6.0.2900.0", dir:"\system32", bulletin:bulletin, kb:kb)
  )
{
  set_kb_item(name:"SMB/Missing/MS10-071", value:TRUE);
  hotfix_security_hole();
  hotfix_check_fversion_end();
  exit(0);
}
else
{
  hotfix_check_fversion_end();
  audit(AUDIT_HOST_NOT, 'affected');
}
