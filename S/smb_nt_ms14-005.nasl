#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(72428);
  script_version("1.15");
  script_cvs_date("Date: 2018/11/15 20:50:31");

  script_cve_id("CVE-2014-0266");
  script_bugtraq_id(65407);
  script_xref(name:"MSFT", value:"MS14-005");
  script_xref(name:"MSKB", value:"2916036");

  script_name(english:"MS14-005: Vulnerability in Microsoft XML Core Services Could Allow Information Disclosure (2916036)");
  script_summary(english:"Checks the file version of Msxml3.dll");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by an information disclosure
vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote host contains a version of Microsoft XML Core Services that
is affected by an information disclosure vulnerability that could allow
an attacker to read files on the local file system of a user, or read
content of web domains where a user is currently authenticated.");
  script_set_attribute(attribute:"see_also", value:"https://docs.microsoft.com/en-us/security-updates/SecurityBulletins/2014/ms14-005");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows XP, 2003, Vista,
2008, 7, 2008 R2, 8, 2012, 8.1 and 2012 R2.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/02/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/02/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/02/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:xml_core_services");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);

  script_copyright(english:"This script is Copyright (C) 2014-2018 Tenable Network Security, Inc.");
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

bulletin = 'MS14-005';
kb = '2916036';

kbs = make_list(kb);
if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

get_kb_item_or_exit("SMB/Registry/Enumerated");
get_kb_item_or_exit("SMB/WindowsVersion", exit_code:1);

if (hotfix_check_sp_range(xp:'3', win2003:'2', vista:'2', win7:'1', win8:'0', win81:'0') <= 0) audit(AUDIT_OS_SP_NOT_VULN);

rootfile = hotfix_get_systemroot();
if (!rootfile) exit(1, "Failed to get the system root.");

share = hotfix_path2share(path:rootfile);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

if (
  # 8.1 / 2012 R2
  hotfix_is_vulnerable(os:"6.3", sp:0, file:"Msxml3.dll", version:"8.110.9600.16483", dir:"\system32", bulletin:bulletin, kb:kb) ||

  # 8.0 / 2012
  hotfix_is_vulnerable(os:"6.2", sp:0, file:"Msxml3.dll", version:"8.110.9200.20890", min_version:"8.110.9200.20000", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.2", sp:0, file:"Msxml3.dll", version:"8.110.9200.16772", min_version:"8.110.9200.16000", dir:"\system32", bulletin:bulletin, kb:kb) ||

  # 7 / 2008 R2
  hotfix_is_vulnerable(os:"6.1", sp:1, file:"Msxml3.dll", version:"8.110.7601.22532", min_version:"8.110.7601.22000", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.1", sp:1, file:"Msxml3.dll", version:"8.110.7601.18334", min_version:"8.110.7600.18000", dir:"\system32", bulletin:bulletin, kb:kb) ||

  # Vista / 2008
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"Msxml3.dll", version:"8.100.5007.0", dir:"\system32", bulletin:bulletin, kb:kb) ||

  # 2003 / XP-64
  hotfix_is_vulnerable(os:"5.2", sp:2, file:"Msxml3.dll", version:"8.100.1054.0", dir:"\system32", bulletin:bulletin, kb:kb) ||

  # XP
  hotfix_is_vulnerable(os:"5.1", sp:3, file:"Msxml3.dll", version:"8.100.1054.0", dir:"\system32", bulletin:bulletin, kb:kb)
)
{
  set_kb_item(name:"SMB/Missing/"+bulletin, value:TRUE);
  hotfix_security_hole();
  hotfix_check_fversion_end();
  exit(0);
}
else
{
  hotfix_check_fversion_end();
  audit(AUDIT_HOST_NOT, 'affected');
}
