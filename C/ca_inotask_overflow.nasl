#
#  (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(25218);
  script_version("1.14");
 script_cvs_date("Date: 2018/11/15 20:50:26");

  script_cve_id("CVE-2007-2523");
  script_bugtraq_id(23906);

  script_name(english:"CA Multiple Products InoCore.dll File Mapping Manipulation Local Overflow");
  script_summary(english:"Checks version of InoCore.dll");

 script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has an application that is affected by a
buffer overflow vulnerability.");
 script_set_attribute(attribute:"description", value:
"The version of CA Anti-Virus for the Enterprise / Threat Manager
installed on the remote host is affected by a stack-based buffer
overflow involving its task service, InoTask.exe. By supplying a long
path to the file job's path, a local attacker can overflow a buffer in
the 'QSIGetQueueID()' function in 'InoCore.dll', leading to possible
command execution with the privileges under which the task service
operates, LOCAL SYSTEM by default.");
 script_set_attribute(attribute:"see_also", value:"https://www.securityfocus.com/archive/1/468306/30/0/threaded");
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a7c65683" );
 script_set_attribute(attribute:"solution", value:
"Ensure that automatic content updates are enabled for the eTrust ITM
Common component and working.");
 script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");

 script_set_attribute(attribute:"vuln_publication_date", value:"2007/05/09");
 script_set_attribute(attribute:"patch_publication_date", value:"2007/05/12");
 script_set_attribute(attribute:"plugin_publication_date", value:"2007/05/16");

script_set_attribute(attribute:"plugin_type", value:"local");
script_end_attributes();


  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2007-2018 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl");
  script_require_keys("SMB/Registry/Enumerated");
  script_require_ports(139, 445);

  exit(0);
}


include("smb_func.inc");
include("audit.inc");


# Connect to the appropriate share.
if (!get_kb_item("SMB/Registry/Enumerated")) exit(0);

name    =  kb_smb_name();
port    =  kb_smb_transport();

login   =  kb_smb_login();
pass    =  kb_smb_password();
domain  =  kb_smb_domain();



if(! smb_session_init()) audit(AUDIT_FN_FAIL, 'smb_session_init');
rc = NetUseAdd(login:login, password:pass, domain:domain, share:"IPC$");
if (rc != 1)
{
  NetUseDel();
  exit(0);
}


# Connect to remote registry.
hklm = RegConnectRegistry(hkey:HKEY_LOCAL_MACHINE);
if (isnull(hklm))
{
  NetUseDel();
  exit(0);
}


# Get some info about the install.
path = NULL;

key = "SOFTWARE\ComputerAssociates\eTrustITM\CurrentVersion\Path";
key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
if (!isnull(key_h))
{
  item = RegQueryValue(handle:key_h, item:"HOME");
  if (!isnull(item)) path = item[1];

  RegCloseKey(handle:key_h);
}
RegCloseKey(handle:hklm);


# If it is...
if (path)
{
  # Make sure the executable exists.
  share = ereg_replace(pattern:"^([A-Za-z]):.*", replace:"\1$", string:path);
  dll =  ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1\InoCore.dll", string:path);
  NetUseDel(close:FALSE);

  rc = NetUseAdd(login:login, password:pass, domain:domain, share:share);
  if (rc != 1)
  {
    NetUseDel();
    exit(0);
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
  }

  # There's a problem if the version is < 8.0.448.0.
  if (!isnull(ver))
  {
    fix = split("8.0.448.0", sep:'.', keep:FALSE);
    for (i=0; i<4; i++)
      fix[i] = int(fix[i]);

    for (i=0; i<max_index(ver); i++)
      if ((ver[i] < fix[i]))
      {
        version = string(ver[0], ".", ver[1], ".", ver[2]);

        report = string(
          "Version ", version, " of the affected file (InoCore.dll) is installed under :\n",
          "\n",
          "  ", path, "\n"
        );
        security_hole(port:port, extra:report);

        break;
      }
      else if (ver[i] > fix[i])
        break;
  }
}


# Clean up.
NetUseDel();
