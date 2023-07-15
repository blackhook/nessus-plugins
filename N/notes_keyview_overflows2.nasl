#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(54922);
  script_version("1.25");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/06/12");

  script_cve_id(
    "CVE-2011-0548",
    "CVE-2011-1213",
    "CVE-2011-1214",
    "CVE-2011-1215",
    "CVE-2011-1216",
    "CVE-2011-1217",
    "CVE-2011-1218",
    "CVE-2011-1512"
  );
  script_bugtraq_id(
    47962,
    48013,
    48016,
    48017,
    48018,
    48019,
    48020,
    48021
  );
  script_xref(name:"CERT", value:"126159");
  script_xref(name:"EDB-ID", value:"17448");
  script_xref(name:"Secunia", value:"44624");

  script_name(english:"IBM Lotus Notes Attachment Handling Multiple Buffer Overflows");
  script_summary(english:"Checks file version of kvgraph.dll");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has an application that is affected by
multiple buffer overflow vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The file attachment viewer component included with the instance of
Lotus Notes installed on the remote Windows host is reportedly
affected by several buffer overflow vulnerabilities that can be
triggered when handling attachments of various types.

By sending a specially crafted attachment to users of the affected
application and getting them to double-click and view the attachment,
an attacker may be able to execute arbitrary code subject to the
privileges under which the affected application runs.");
  script_set_attribute(attribute:"see_also", value:"https://www.securityfocus.com/archive/1/518139");
  script_set_attribute(attribute:"see_also", value:"https://www.securityfocus.com/archive/1/518131");
  script_set_attribute(attribute:"see_also", value:"https://www.securityfocus.com/archive/1/518138");
  script_set_attribute(attribute:"see_also", value:"https://www.securityfocus.com/archive/1/518137");
  # https://www.secureauth.com/labs/advisories/LotusNotes-XLS-viewer-heap-overflow
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c85aef3a");
  script_set_attribute(attribute:"see_also", value:"https://seclists.org/bugtraq/2011/May/178");
  script_set_attribute(attribute:"see_also", value:"https://seclists.org/bugtraq/2011/May/179");
  script_set_attribute(attribute:"see_also", value:"https://seclists.org/bugtraq/2011/May/181");
  script_set_attribute(attribute:"see_also", value:"https://seclists.org/bugtraq/2011/May/182");
  script_set_attribute(attribute:"see_also", value:"https://www.securityfocus.com/archive/1/archive/1/518120/100/0/threaded");
  script_set_attribute(attribute:"see_also", value:"https://www-304.ibm.com/support/docview.wss?uid=swg21500034");
  script_set_attribute(attribute:"solution", value:
"Either Install Interim Fix 1 for Notes 8.5.2 Fix Pack 2 / 8.5.2 Fix
Pack 3 or upgrade to 8.5.3. Alternatively, disable attachment viewers.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2011-0548");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Lotus Notes 8.0.x - 8.5.2 FP2 - Autonomy Keyview (.lzh Attachment)');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

script_set_attribute(attribute:"vuln_publication_date", value:"2011/05/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/05/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/05/31");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:lotus_notes");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2011-2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("smb_hotfixes.nasl","lotus_notes_installed.nasl");
  script_require_keys("SMB/Registry/Enumerated","SMB/Lotus_Notes/Installed");
  script_require_ports(139, 445);

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("smb_func.inc");
include("audit.inc");
include("smb_hotfixes_fcheck.inc");
include("smb_reg_query.inc");

kb_base = "SMB/Lotus_Notes/";

version = get_kb_item_or_exit(kb_base + 'Version');
path = get_kb_item_or_exit(kb_base + 'Path');

get_kb_item_or_exit("SMB/Registry/Enumerated");

# Retrieve the appropriate share.
port    =  kb_smb_transport();
login   =  kb_smb_login();
pass    =  kb_smb_password();
domain  =  kb_smb_domain();

# Get a list of user data dirs on the system
registry_init();
hku = registry_hive_connect(hive:HKEY_USERS, exit_on_fail:TRUE);
if (empty_or_null(hku))
{
  RegCloseKey(handle:hku);
  close_registry();
  audit(AUDIT_REG_FAIL);
}
key_h = RegOpenKey(handle:hku, mode:MAXIMUM_ALLOWED);
if (!empty_or_null(key_h))
{
  reginfo = RegQueryInfoKey(handle:key_h);
}

if (!empty_or_null(reginfo))
{
  datadirs = [];
  registry_init();
  for (i = 0; i < reginfo[1]; i++)
  {
    subkey = RegEnumKey(handle:key_h, index:i);
    key = subkey + "\Software\IBM\Notes\Installer\DATADIR";
    datadir = get_registry_value(handle:hku, item:key);
    if (empty_or_null(datadir))
    {
      key = subkey + "\Software\Lotus\Notes\Installer\DATADIR";
      datadir = get_registry_value(handle:hku, item:key);
    }
    if (!empty_or_null(datadir) && subkey =~ '^S-1-5-21-[0-9\\-]+$')
    {
      datadirs[max_index(datadirs)] = datadir;
    }
  }
  RegCloseKey(handle:key_h);
  RegCloseKey(handle:hku);
  close_registry();
}

if(! smb_session_init()) audit(AUDIT_FN_FAIL, 'smb_session_init');

# Split the software's location into components.
base = preg_replace(string:path, pattern:"^(.+)\\$", replace:"\1");
share = preg_replace(string:base, pattern:"^([A-Za-z]):.*", replace:"\1$");
path = preg_replace(string:base, pattern:"^[A-Za-z]:(.*)", replace:"\1");
found = FALSE;

# Connect to the share software is installed on.
rc = NetUseAdd(login:login, password:pass, domain:domain, share:share);
if (rc != 1)
{
  NetUseDel();
  audit(AUDIT_SHARE_FAIL, share);
}
if (!empty_or_null(datadirs))
{
  foreach datadir (datadirs)
  {
    file = preg_replace(string:datadir, pattern:"^[A-Za-z]:(.*)", replace:"\1") + "\KeyView.ini";
    file_h = CreateFile(
      file:file,
      desired_access:GENERIC_READ,
      file_attributes:FILE_ATTRIBUTE_NORMAL,
      share_mode:FILE_SHARE_READ,
      create_disposition:OPEN_EXISTING
    );
    if (!empty_or_null(file_h))
    {
      found = TRUE;
    }
  }
  file = preg_replace(string:base, pattern:"^[A-Za-z]:(.*)", replace:"\1") + "\KeyView.ini";
  file_h = CreateFile(
    file:file,
    desired_access:GENERIC_READ,
    file_attributes:FILE_ATTRIBUTE_NORMAL,
    share_mode:FILE_SHARE_READ,
    create_disposition:OPEN_EXISTING
  );
  if (!empty_or_null(file_h))
  {
    found = TRUE;
  }
  CloseFile(handle:file_h);

  if (!found)
  {
    NetUseDel();
    audit(AUDIT_INST_VER_NOT_VULN, "IBM Notes");
  }
}

# Try and read one of the vulnerable files.
file_h = CreateFile(
  file:path + "\xlssr.dll",
  desired_access:GENERIC_READ,
  file_attributes:FILE_ATTRIBUTE_NORMAL,
  share_mode:FILE_SHARE_READ,
  create_disposition:OPEN_EXISTING
);
if (isnull(file_h))
{
  NetUseDel();
  audit(AUDIT_INST_VER_NOT_VULN, "IBM Notes");
}

version = GetFileVersion(handle:file_h);
CloseFile(handle:file_h);
NetUseDel();
if (isnull(version)) exit(1, "Failed to extract the file version from '" + base + "\xlssr.dll'.");

# Check if the DLL file is vulnerable.
fix = "8.5.23.11191";
ver = join(version, sep:".");
if (ver_compare(ver:ver, fix:fix) >= 0)
  audit(AUDIT_INST_VER_NOT_VULN, "IBM Notes");

# Report our findings.
report =
  '\n  File              : ' + base + "\xlssr.dll" +
  '\n  Installed version : ' + ver +
  '\n  Fixed version     : ' + fix +
  '\n';
security_report_v4(port:445, severity:SECURITY_HOLE, extra:report);
