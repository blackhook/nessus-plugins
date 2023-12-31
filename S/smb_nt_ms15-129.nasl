#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(87258);
  script_version("1.9");
  script_cvs_date("Date: 2018/11/15 20:50:31");

  script_cve_id("CVE-2015-6114", "CVE-2015-6165", "CVE-2015-6166");
  script_bugtraq_id(78502, 78504, 78505);
  script_xref(name:"MSFT", value:"MS15-129");
  script_xref(name:"MSKB", value:"3106614");

  script_name(english:"MS15-129: Security Update for Silverlight to Address Remote Code Execution (3106614)");
  script_summary(english:"Checks the version of Microsoft Silverlight.exe.");

  script_set_attribute(attribute:"synopsis", value:
"A multimedia application framework installed on the remote Windows
host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Microsoft Silverlight installed on the remote Windows
host is affected by the following vulnerabilities :

  - Multiple information disclosure vulnerabilities exist
    due to a failure to properly handle objects in memory.
    An attacker can exploit these issues, via crafted
    Silverlight content, to more reliably predict pointer
    values and thus degrade the effectiveness of the Address
    Space Layout Randomization (ASLR) security feature,
    allowing the system to be further compromised.
    (CVE-2015-6114, CVE-2015-6165)

  - A remote code execution vulnerability exists due to
    incorrect handling of certain open and close requests,
    which result in read and write access violations. A
    remote attacker can exploit this vulnerability, via a
    specially crafted Silverlight application, to gain
    privileges and take complete control of the affected
    host. (CVE-2015-6166)");
  script_set_attribute(attribute:"see_also", value:"https://docs.microsoft.com/en-us/security-updates/SecurityBulletins/2015/ms15-129");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Silverlight 5.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/12/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/12/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/12/08");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:silverlight");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2015-2018 Tenable Network Security, Inc.");

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

bulletin = 'MS15-129';
kb = "3106614";

kbs = make_list(kb);
if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

get_kb_item_or_exit("SMB/Registry/Enumerated");

# Silverlight 5.x
ver = get_kb_item("SMB/Silverlight/Version");
if (isnull(ver)) audit(AUDIT_NOT_INST, "Silverlight");
if (ver !~ "^5\.") audit(AUDIT_NOT_INST, "Silverlight 5");

fix = "5.1.41105.0";
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
