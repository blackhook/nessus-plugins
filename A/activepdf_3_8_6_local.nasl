#
#  (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(31350);
  script_version("1.17");
 script_cvs_date("Date: 2018/11/15 20:50:26");

  script_cve_id("CVE-2007-5397");
  script_bugtraq_id(28013);
  script_xref(name:"Secunia", value:"27371");

  script_name(english:"activePDF Server < 3.8.6 Packet Handling Remote Overflow (credentialed check)");
  script_summary(english:"Checks version of APServer.exe");

 script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains a program that is affected by a
buffer overflow vulnerability.");
 script_set_attribute(attribute:"description", value:
"activePDF Server is installed on the remote host. It is used to
provide PDF generation and conversion from within enterprise and web
applications.

The version of activePDF Server installed on the remote host contains
a heap-based buffer overflow that can be triggered by sending a packet
specifying a size smaller than the actual size of the following data.
An unauthenticated, remote attacker may be able to leverage this issue
to crash the affected service or execute arbitrary code.

Note that the service runs with SYSTEM privileges, so successful
exploitation could lead to a complete compromise of the affected host.");
 script_set_attribute(attribute:"see_also", value:"https://secuniaresearch.flexerasoftware.com/secunia_research/2007-87/advisory");
 script_set_attribute(attribute:"see_also", value:"http://www.activepdf.com/support/knowledgebase/viewKb.cfm?fs=1&ID=11744" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to activePDF version 3.8.6 or later and make sure the file
version for the affected file is 3.8.6.15 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
 script_cwe_id(119);

 script_set_attribute(attribute:"plugin_publication_date", value:"2008/03/05");

script_set_attribute(attribute:"plugin_type", value:"local");
script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");
  script_copyright(english:"This script is Copyright (C) 2008-2018 Tenable Network Security, Inc.");
  script_dependencies("smb_hotfixes.nasl");
  script_require_keys("SMB/Registry/Enumerated");
  script_require_ports(139, 445);
  exit(0);
}

#

include("global_settings.inc");
include("smb_func.inc");

if (!get_kb_item("SMB/Registry/Enumerated")) exit(0);


# Connect to the appropriate share.
name    =  kb_smb_name();
port    =  kb_smb_transport();
#if (!get_port_state(port)) exit(0);
login   =  kb_smb_login();
pass    =  kb_smb_password();
domain  =  kb_smb_domain();

#soc = open_sock_tcp(port);
#if (!soc) exit(0);

#session_init(socket:soc, hostname:name);

if (!smb_session_init()) exit(0);

rc = NetUseAdd(login:login, password:pass, domain:domain, share:"IPC$");
if (rc != 1) {
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


# Make sure it's installed.
exe = NULL;

key = "SYSTEM\CurrentControlSet\Services\A4ACTIVEPDFSERVER";
key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
if (!isnull(key_h))
{
  value = RegQueryValue(handle:key_h, item:"ImagePath");
  if (!isnull(value)) exe = value[1];

  RegCloseKey(handle:key_h);
}
RegCloseKey(handle:hklm);
if (isnull(exe))
{
  NetUseDel();
  exit(0);
}


# Grab the file version of the affected file.
share = ereg_replace(pattern:"^([A-Za-z]):.*", replace:"\1$", string:exe);
exe2 =  ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1", string:exe);
NetUseDel(close:FALSE);

rc = NetUseAdd(login:login, password:pass, domain:domain, share:share);
if (rc != 1)
{
  NetUseDel();
  exit(0);
}

fh = CreateFile(
  file:exe2,
  desired_access:GENERIC_READ,
  file_attributes:FILE_ATTRIBUTE_NORMAL,
  share_mode:FILE_SHARE_READ,
  create_disposition:OPEN_EXISTING
);
ver = NULL;
if (!isnull(fh))
{
  ver = GetFileVersion(handle:fh);
  CloseFile(handle:fh);
}
NetUseDel();


# Check the version number.
if (!isnull(ver))
{
  # nb: while the release notes talk of 3.8.6.16, that appears to
  #     be a mistake -- the release of 3.8.6 on 28-Feb-2008 was
  #     3.8.6.15. And testing shows it fixes the problem. The
  #     previous release was 3.8.5, which was affected.
  fix = split("3.8.6.15", sep:'.', keep:FALSE);
  for (i=0; i<max_index(fix); i++)
    fix[i] = int(fix[i]);

  for (i=0; i<max_index(ver); i++)
    if ((ver[i] < fix[i]))
    {
      # nb: the file version isn't always up-to-date so I won't report it.
      security_hole(port);
      break;
    }
    else if (ver[i] > fix[i])
      break;
}
