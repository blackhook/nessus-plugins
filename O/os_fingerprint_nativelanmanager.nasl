#
# (C) Tenable Network Secrity, Inc.
#

include("compat.inc");

if (description)
{
  script_id(58604);
  script_version("2.15");
  script_cvs_date("Date: 2020/01/22");

  script_name(english:"OS Identification : NativeLanManager");
  script_summary(english:"Checks the remote native LAN manager name.");

  script_set_attribute(attribute:"synopsis", value:
"It is possible to identify the remote operating system based on the
SMB remote native LAN manager name (NativeLanManager).");
  script_set_attribute(attribute:"description", value:
"The remote operating system can be identified based on its responses
to an SMB authentication request.");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2012/04/05");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"asset_inventory", value:"True");
  script_set_attribute(attribute:"os_identification", value:"True");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"General");

  script_copyright(english:"This script is Copyright (C) 2012-2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("smb_nativelanman.nasl");
  script_require_keys("SMB/NativeLanManager");

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");

os = NULL;
# nb: since the version info for Mac OS X isn't granular, keep it
#     under 70, which is the cutoff used by OS version checks, at
#     least for that OS.
confidence = 69;
type = 'general-purpose';

nativelanman = get_kb_item_or_exit('SMB/NativeLanManager');

if ('Samba 3.0.25b-apple' >< nativelanman) os = 'Mac OS X 10.5';
else if ('Samba 3.0.28a-apple' >< nativelanman) os = 'Mac OS X 10.6';
else if ('(#)PROGRAM:smbd  PROJECT:smbx-103' >< nativelanman) os = 'Mac OS X 10.7';
else if ('(#)PROGRAM:smbd  PROJECT:smbx-105' >< nativelanman) os = 'Mac OS X 10.7';
else if ('(#)PROGRAM:smbd  PROJECT:smbx-128' >< nativelanman) os = 'Mac OS X 10.8 DP1';
else if ('(#)PROGRAM:smbd  PROJECT:smbx-136' >< nativelanman) os = 'Mac OS X 10.8';
else if ('@(#)PROGRAM:smbd  PROJECT:smbx-275' >< nativelanman ) os = 'Mac OS X 10.9';
else if ('@(#)PROGRAM:smbd  PROJECT:smbx-316' >< nativelanman ) os = 'Mac OS X 10.10'; # build 14A238x (beta)

else if ('iSeries Support for Windows Network Neighborhood' >< nativelanman)
{
  os = "IBM OS/400";
  confidence = 95;
}
else if ('Isilon OneFS' >< nativelanman)
{
  os = "Isilon OneFS";
  confidence = 95;
  type = "embedded";
}
else if ('GuardianOS' >< nativelanman)
{
  os = 'GuardianOS';
  match = pregmatch(string:nativelanman, pattern:"GuardianOS v\.?([0-9.]+)");
  if (!isnull(match)) {
    os = 'GuardianOS ' + match[1];
  }
  
  confidence = 95;
  type = "embedded";
}

# Solaris
else if ('SunOS 5.11 LAN Manager'  >< nativelanman) os = "Solaris 11";
else if ('SunOS 5.10 LAN Manager'  >< nativelanman) os = "Solaris 10";
else if ('SunOS 5.9 LAN Manager'   >< nativelanman) os = "Solaris 9";
else if ('SunOS 5.8 LAN Manager'   >< nativelanman) os = "Solaris 8";
else if ('SunOS 5.7 LAN Manager'   >< nativelanman) os = "Solaris 7";
else if ('SunOS 5.6 LAN Manager'   >< nativelanman) os = "Solaris 2.6";
else if ('SunOS 5.5.1 LAN Manager' >< nativelanman) os = "Solaris 2.5.1";
else if ('SunOS 5.5 LAN Manager'   >< nativelanman) os = "Solaris 2.5";
else if ('SunOS 5.4 LAN Manager'   >< nativelanman) os = "Solaris 2.4";
else if ('SunOS 5.3 LAN Manager'   >< nativelanman) os = "Solaris 2.3";
else if ('SunOS 5.2 LAN Manager'   >< nativelanman) os = "Solaris 2.2";
else if ('SunOS 5.1 LAN Manager'   >< nativelanman) os = "Solaris 2.1";
else if ('SunOS 5.0 LAN Manager'   >< nativelanman) os = "Solaris 2.0";

if (os =~ "^Solaris")
{
  confidence = 95;

  # More granular versions of the 11 branch (e.g. 11.3) exist but
  # we can't deduce it from the SunOS version so lower confidence
  if (os == "Solaris 11")
    confidence -= 10;
}

if (!empty_or_null(os))
{
  set_kb_item(name:'Host/OS/NativeLanManager', value:os);
  set_kb_item(name:'Host/OS/NativeLanManager/Confidence', value:confidence);
  set_kb_item(name:'Host/OS/NativeLanManager/Type', value:type);
}
