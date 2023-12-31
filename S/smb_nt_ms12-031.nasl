#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(59039);
  script_version("1.15");
  script_cvs_date("Date: 2018/11/15 20:50:31");

  script_cve_id("CVE-2012-0018");
  script_bugtraq_id(53328);
  script_xref(name:"MSFT", value:"MS12-031");
  script_xref(name:"MSKB", value:"2597981");

  script_name(english:"MS12-031: Vulnerability in Microsoft Visio Viewer 2010 Could Allow Remote Code Execution (2597981)");
  script_summary(english:"Checks the version of Vviewer.dll");

  script_set_attribute(attribute:"synopsis", value:
"Arbitrary code can be executed on the remote host through Microsoft
Visio Viewer.");
  script_set_attribute(attribute:"description", value:
"The version of Microsoft Visio Viewer installed on the remote Windows
host is reportedly affected by a memory corruption vulnerability due
to the way the application handles memory when parsing specially
crafted Visio files.

An attacker who tricked a user on the affected host into opening a
specially crafted Visio file could leverage this issue to execute
arbitrary code in the context of the current user.");

  script_set_attribute(attribute:"see_also", value:"https://docs.microsoft.com/en-us/security-updates/SecurityBulletins/2012/ms12-031");
  script_set_attribute(attribute:"solution", value:"Microsoft has released a set of patches for Visio Viewer 2010.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/05/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/05/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/05/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:visio_viewer");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2012-2018 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl", "ms_bulletin_checks_possible.nasl");
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

bulletin = "MS12-031";
kb = "2597981";

kbs = make_list(kb);
if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

get_kb_item_or_exit("SMB/Registry/Enumerated", exit_code:1);
get_kb_item_or_exit("SMB/WindowsVersion", exit_code:1);

# Determine the install path for Visio Viewer 2010.
visio_viewer_path = NULL;

port    =  kb_smb_transport();
login   =  kb_smb_login();
pass    =  kb_smb_password();
domain  =  kb_smb_domain();

if(! smb_session_init()) audit(AUDIT_FN_FAIL, "smb_session_init");

hcf_init = TRUE;
rc = NetUseAdd(login:login, password:pass, domain:domain, share:"IPC$");
if (rc != 1)
{
  NetUseDel();
  audit(AUDIT_SHARE_FAIL, "IPC");
}

# Connect to remote registry.
hklm = RegConnectRegistry(hkey:HKEY_LOCAL_MACHINE);
if (isnull(hklm))
{
  NetUseDel();
  audit(AUDIT_REG_FAIL);
}

key = "SOFTWARE\Microsoft\Office\14.0\Common\InstallRoot";
key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
if (!isnull(key_h))
{
  value = RegQueryValue(handle:key_h, item:"Path");
  if (value) visio_viewer_path = value[1];

  RegCloseKey(handle:key_h);
}
RegCloseKey(handle:hklm);
NetUseDel(close:FALSE);

vuln = FALSE;

# Visio Viewer 2010.
if (visio_viewer_path)
{
  share = ereg_replace(pattern:"^([A-Za-z]):.*", replace:"\1$", string:visio_viewer_path);
  if (!is_accessible_share(share:share))
    audit(AUDIT_SHARE_FAIL, share);

  if (hotfix_check_fversion(path:visio_viewer_path, file:"Vviewer.dll", version:"14.0.6117.5003", min_version:"14.0.0.0", bulletin:bulletin, kb:kb) == HCF_OLDER)
    vuln = TRUE;
}

if (vuln)
{
  set_kb_item(name:"SMB/Missing/" + bulletin, value:TRUE);
  hotfix_security_hole();

  hotfix_check_fversion_end();
  exit(0);
}
else
{
  hotfix_check_fversion_end();
  exit(0, "The host is not affected.");
}
