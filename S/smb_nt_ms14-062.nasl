#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(78438);
  script_version("1.11");
  script_cvs_date("Date: 2018/11/15 20:50:31");

  script_cve_id("CVE-2014-4971");
  script_bugtraq_id(68764);
  script_xref(name:"EDB-ID", value:"34982");
  script_xref(name:"MSFT", value:"MS14-062");
  script_xref(name:"MSKB", value:"2993254");
  script_xref(name:"IAVA", value:"2014-A-0150");

  script_name(english:"MS14-062: Vulnerability in Message Queuing Service Could Allow Elevation of Privilege (2993254)");
  script_summary(english:"Checks presence of MSMQ service / version of Mqqm.dll.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host is affected by a privilege escalation
vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote Windows host is affected by a privilege escalation
vulnerability in the Microsoft Message Queuing (MSMQ) service. The
vulnerability can be exploited if an attacker sends a specially
crafted input/output control (IOCTL) request to the Message Queuing
service. Successful exploitation of this vulnerability could lead to
full access to the affected system.");
  script_set_attribute(attribute:"see_also", value:"https://docs.microsoft.com/en-us/security-updates/SecurityBulletins/2014/ms14-062");
  script_set_attribute(attribute:"solution", value:"Microsoft has released a set of patches for Windows 2003.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'MQAC.sys Arbitrary Write Privilege Escalation');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/10/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/10/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/10/15");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2014-2018 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl", "smb_enum_services.nasl", "ms_bulletin_checks_possible.nasl");
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

bulletin = 'MS14-062';
kb = "2993254";

kbs = make_list(kb);
if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

get_kb_item_or_exit("SMB/Registry/Enumerated");
get_kb_item_or_exit("SMB/WindowsVersion", exit_code:1);

if (hotfix_check_sp_range(win2003:'2') <= 0) audit(AUDIT_OS_SP_NOT_VULN);

share = hotfix_get_systemdrive(as_share:TRUE, exit_on_fail:TRUE);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

if (
  # Windows Server 2003
  hotfix_is_vulnerable(os:"5.2", sp:2, file:"Mqqm.dll", version:"5.2.2008.5417", dir:"\system32", bulletin:bulletin, kb:kb)
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
