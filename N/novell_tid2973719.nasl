#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description) {
  script_id(21340);
  script_version("1.16");
  script_cvs_date("Date: 2018/07/16 14:09:15");

  script_cve_id("CVE-2006-2304");
  script_bugtraq_id(17931);

  script_name(english:"Novell Client for Windows DPRPC library (DPRPCW32.DLL) ndps_xdr_array Function Remote Overflow");
  script_summary(english:"Checks file version of dprpcw32.dll");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains a DLL that suffers from a buffer
overflow flaw.");
  script_set_attribute(attribute:"description", value:
"The file 'dprpcw32.dll' included with the Novell Client software
reportedly contains a potential buffer overflow.");
  # http://computergroups.net/novell.support.newsflash/what-s-new-since-5-9-06/3770
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?1255bf65");
  script_set_attribute(attribute:"solution", value:
"Install the 491psp2_dprpcw32.exe beta patch file referenced in the
vendor advisory above.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2006/05/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2006/05/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/05/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");
  script_copyright(english:"This script is Copyright (C) 2006-2018 Tenable Network Security, Inc.");
  script_dependencies("smb_hotfixes.nasl");
  script_require_keys("SMB/Registry/Enumerated");
  script_require_ports(139, 445);
  exit(0);
}

#

include("audit.inc");
include("misc_func.inc");
include("smb_func.inc");
include("smb_hotfixes.inc");


if (!get_kb_item("SMB/Registry/Enumerated")) exit(1, "KB 'SMB/Registry/Enumerated' not set to TRUE.");


# Unless we're being paranoid, check whether the software's installed.
if (report_paranoia < 2)
{
  subkey = "{Novell Client for Windows}";
  key = string("SMB/Registry/HKLM/SOFTWARE/Microsoft/Windows/CurrentVersion/Uninstall/", subkey, "/DisplayName");
  get_kb_item_or_exit(key);
}


# Connect to the appropriate share.
port    =  kb_smb_transport();
login   =  kb_smb_login();
pass    =  kb_smb_password();
domain  =  kb_smb_domain();

if(! smb_session_init()) audit(AUDIT_FN_FAIL, 'smb_session_init');

# Check the version of dprpcw32.dll.
winroot = hotfix_get_systemroot();
if (!winroot) exit(1);

share = ereg_replace(pattern:"^([A-Za-z]):.*", replace:"\1$", string:winroot);
dll =  ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1\System32\dprpcw32.dll", string:winroot);

rc = NetUseAdd(login:login, password:pass, domain:domain, share:share);
if (rc != 1)
{
  NetUseDel();
  audit(AUDIT_SHARE_FAIL,share);
}

fh = CreateFile(
  file:dll,
  desired_access:GENERIC_READ,
  file_attributes:FILE_ATTRIBUTE_NORMAL,
  share_mode:FILE_SHARE_READ,
  create_disposition:OPEN_EXISTING
);
if (!isnull(fh))
{
  ver = GetFileVersion(handle:fh);
  CloseFile(handle:fh);

  # nb: for older versions, the file version will be null.
  if (isnull(ver)) security_hole(get_kb_item("SMB/transport"));
  else if (
    # nb: version of the patch is 3.0.2.0.
    int(ver[0]) < 3 ||
    (int(ver[0]) == 3 && int(ver[1]) == 0 && int(ver[2]) < 2)
  ) security_hole(get_kb_item("SMB/transport"));
}
NetUseDel();
