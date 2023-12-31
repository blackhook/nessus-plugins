#
# (C) Tenable Network Security, Inc.
#




include("compat.inc");

if (description)
{
  script_id(72932);
  script_version("1.13");
  script_cvs_date("Date: 2019/11/26");

  script_cve_id("CVE-2014-0319");
  script_bugtraq_id(66046);
  script_xref(name:"MSFT", value:"MS14-014");
  script_xref(name:"MSKB", value:"2932677");

  script_name(english:"MS14-014: Vulnerability in Silverlight Could Allow Security Feature Bypass (2932677)");
  script_summary(english:"Checks version of Silverlight.exe");

  script_set_attribute(attribute:"synopsis", value:
"A browser enhancement on the remote Windows host is affected by a
security feature bypass vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Microsoft Silverlight installed on the remote host is
reportedly affected by a security feature bypass vulnerability due to
improper implementation of Data Execution Protection (DEP) and Address
Space Layout Randomization (ASLR). 

If an attacker could trick a user on the affected system into visiting a
website hosting a malicious Silverlight application, the attacker could
bypass the DEP and ASLR security features.");
  script_set_attribute(attribute:"see_also", value:"https://docs.microsoft.com/en-us/security-updates/SecurityBulletins/2014/ms14-014");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Silverlight 5.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:C/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2014-0319");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/03/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/03/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/03/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:silverlight");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2014-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("smb_hotfixes.nasl", "silverlight_detect.nasl", "ms_bulletin_checks_possible.nasl");
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

bulletin = 'MS14-014';
kb = "2932677";

kbs = make_list(kb);
if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

get_kb_item_or_exit("SMB/Registry/Enumerated");

# Silverlight 5.x
ver = get_kb_item("SMB/Silverlight/Version");
if (isnull(ver)) audit(AUDIT_NOT_INST, "Silverlight");
if (ver !~ "^5\.") audit(AUDIT_NOT_INST, "Silverlight 5");

fix = "5.1.30214.0";
if (ver_compare(ver:ver, fix:fix) == -1)
{
  path = get_kb_item("SMB/Silverlight/Path");
  if (isnull(path)) path = 'n/a';

  report +=
    '\n  Path              : ' + path +
    '\n  Installed version : ' + ver +
    '\n  Fixed version     : ' + fix +
    '\n';
  hotfix_add_report(report, bulletin:bulletin, kb:kb);

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
