#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');
include('debug.inc');
if (description)
{
  script_id(25251);
  script_version("1.44");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/09/22");

  script_name(english:"OS Identification : Unix uname");
  script_summary(english:"Determines the remote operating system");

  script_set_attribute(attribute:"synopsis", value:
"It is possible to identify the remote operating system based on the response returned by 'uname -a'.");
  script_set_attribute(attribute:"description", value:
"This script attempts to identify the Operating System type and version by looking at the data returned by 'uname -a'.");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2007/05/19");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"asset_inventory", value:"True");
  script_set_attribute(attribute:"os_identification", value:"True");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2007-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"General");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/uname");
  exit(0);
}

# uname -a printing from BSD
# PRINT_FLAG(flags, SFLAG, sysname);
# PRINT_FLAG(flags, NFLAG, hostname);
# PRINT_FLAG(flags, RFLAG, release);
# PRINT_FLAG(flags, VFLAG, version);
# PRINT_FLAG(flags, MFLAG, platform);
# PRINT_FLAG(flags, PFLAG, arch);
# PRINT_FLAG(flags, IFLAG, ident);
# PRINT_FLAG(flags, KFLAG, kernvers);
# PRINT_FLAG(flags, UFLAG, uservers);

var kb, match, os, kernel, release, matches, ver, num, oslevel, oslevelsp;
var uname = get_kb_item_or_exit("Host/uname");
var reject_unames = ["invalid", "please", "not supported", "help"];
var uname_rejected = FALSE;
foreach var reject (reject_unames)
{
  if (uname =~ reject)
    uname_rejected = TRUE;
}
if ( uname_rejected ) exit(1, "Reported uname '" + uname + "' seems to be invalid.");

set_kb_item(name:"Host/OS/uname/Fingerprint", value:uname);

var array = pregmatch(pattern:"^([^ ]+) +([^ ]+) +([^ ]+) +([^ ]*)", string:uname);
if ( isnull(array) ) exit(1, "The uname '" + uname + "' is not in the expected format.");
var confidence = 100;
var type = "general-purpose";

if ( array[1] == "Linux" )
{
  kb = get_kb_item("Host/etc/redhat-release");

  match = pregmatch(pattern:"^(.+)\.([^.]*LEAF)$", string:array[3]);
  if ('-LEAF' >< array[3] && !isnull(match))
  {
   os = "Linux Kernel " + match[1] + ' on ' + match[2];
   type = "embedded";
  }
  else if (array[3] =~ "\.amzn[0-9]+\.")
  {
    os = "Amazon Linux AMI";
    kb = get_kb_item("Host/AmazonLinux/release");
    if (!isnull(kb) && os >< kb)
    {
      match = pregmatch(pattern:"^ALA([0-9]+\.[0-9.]+)", string:kb);
      if (!isnull(match)) os += " " + match[1];
    }

    # specific to Amazon Linux 2 release
    if (!empty_or_null(kb) && preg(pattern:"^AL2-", string:kb))
    {
      os = "Amazon Linux 2";
    }
    # specific to Amazon Linux yearly releases
    match = pregmatch(pattern:"^AL-([0-9]+(?:\.[0-9.]+)?)-", string:kb);
    if (!empty_or_null(match) && !empty_or_null(match[1]))
    {
      os = "Amazon Linux " + match[1];
    }

    kernel = preg_replace(pattern:"\.amzn[0-9]+\..+$", replace:"", string:array[3]);
    if (kernel =~ "^[0-9]+\.[0-9.-]+$") os = "Linux Kernel " + array[3] + " on " + os;
  }
  else if (array[3] =~ "\.mlos[0-9]+\.mwg")
  {
    os = "McAfee Linux OS";
    if (!isnull(kb) && os >< kb)
    {
      match = pregmatch(pattern:"^McAfee Linux OS release ([0-9]+\.[0-9.]+)", string:kb);
      if (!isnull(match)) os += " " + match[1];
    }

    kernel = ereg_replace(pattern:"\.mlos[0-9]+\.mwg\..+$", replace:"", string:array[3]);
    if (kernel =~ "^[0-9]+\.[0-9.-]+$") os = "Linux Kernel " + array[3] + " on " + os;
  }
  else if (array[3] =~ "uek$" && !isnull(kb) && "Oracle VM server" >< kb)
  {
    os = "Oracle VM Server";
    match = pregmatch(pattern:"^Oracle VM server release ([0-9]+\.[0-9.]+)", string:kb);
    if (!isnull(match)) os += " " + match[1];

    kernel = ereg_replace(pattern:"\.mlos[0-9]+\.mwg\..+$", replace:"", string:array[3]);
    if (kernel =~ "^[0-9]+\.[0-9.-]+$") os = "Linux Kernel " + array[3] + " on " + os;
  }
  else if (!isnull(kb) && "PelcoLinux" >< kb)
  {
    os = "PelcoLinux";
    match = pregmatch(pattern:"^PelcoLinux release ([0-9]+[0-9.]*)", string:kb);
    if (!isnull(match)) os += " release " + match[1];

    os = "Linux Kernel " + array[3] + " on " + os;
  }
  else if (array[3] =~ "-coreos$")
  {
    os = "Container Linux by CoreOS";
    release = get_kb_item("Host/Container Linux by CoreOS/release");
    if (!isnull(release))
    {
      matches = pregmatch(pattern:"^(CoreOS|Container Linux by CoreOS) ([0-9]+\.[0-9.]+)", string:release);
      if (!isnull(matches)) os = matches[0];
    }

    kernel = preg_replace(pattern:"-coreos", replace:"", string:array[3]);
    if (kernel =~ "^[0-9]+\.[0-9.-]+$") os = "Linux Kernel " + array[3] + " on " + os;
  }
  else if (array[3] =~ "WR[0-9.]+")
  {
    os = "Wind River Linux";
    if (!isnull(kb) && os >< kb)
    {
      match = pregmatch(pattern:"^WR[0-9.]+", string:kb);
      if (!isnull(match)) os += " " + match[1];
    }
    kernel = ereg_replace(pattern:"^WR[0-9.]+", replace:"", string:array[3]);
    if (kernel =~ "^[0-9]+\.[0-9.-]+$") os = "Linux Kernel " + array[3] + " on " + os;
  }
  else if (array[3] =~ "[0-9.]+-[0-9]+cp")
  {
    os = "Check Point Gaia";
    release = get_kb_item("Host/Check_Point/version");
    if(!isnull(release))
      os += " release " + release;
    kernel = ereg_replace(pattern:"cp(x86_64)?", replace:"", string:array[3]);
    if (kernel =~ "^[0-9.]+-[0-9]+$")
      os = "Linux Kernel " + array[3] + " on " + os;
  }
  else if ("almalinux" >< array[2])
  {
    os = get_kb_item("Host/AlmaLinux/release");
    kernel = ereg_replace(pattern:"el[0-9.]?(\.x86_64)?", replace:"", string:array[3]);
    if (kernel =~ "^[0-9]+\.[0-9.-]+$")
      os = "Linux Kernel " + array[3] + " on " + os;
  }
  else if ("rockylinux" >< array[2])
  {
    os = get_kb_item("Host/RockyLinux/release");
    kernel = ereg_replace(pattern:"el[0-9.]?\_?[0-9.]?(\.x86_64)?", replace:"", string:array[3]);
    if (kernel =~ "^[0-9]+\.[0-9.-]+$")
      os = "Linux Kernel " + array[3] + " on " + os;
  }
  else if ("nutanix" >< array[3])
  {
    os = "Linux Kernel " + array[3] + " on Nutanix";

    var nextra;
    var nserv = get_kb_item("Host/Nutanix/Data/Service");
    var nver = get_kb_item("Host/Nutanix/Data/Version");
    if (!empty_or_null(nserv))
      nextra = strcat(" ", nserv);
    if (!empty_or_null(nver))
      nextra = strcat(nextra, " ", nver);

    if(!empty_or_null(nextra))
      os = strcat(os, nextra);
  }
  else if (array[3] =~ "^[\d.]+-qnap$")
  {
    match = pregmatch(pattern:"^([\d.]+)-qnap$", string:array[3]);
    if (match)
    {
      os = strcat('Linux Kernel ', match[1], ' QNAP', match[2]);
      confidence -= 5;
    }
  }
  else
  {
    kb = get_kb_item("Host/etc/Eos-release");
    if(!isnull(kb) && "Arista Networks EOS" >< kb)
    {
      ver = get_kb_item("Host/Arista-EOS/Version");
      if(isnull(ver)) ver = '';
      os = "Arista EOS " + ver;
      os = "Linux Kernel " + array[3] + " on " + os;
      type = "switch";
    }
    else
    {
      os = "Linux Kernel " + array[3];
      confidence --; # we don't have the distribution
    }
  }
}
else if ( array[1] == "Darwin" )
{
  os = get_kb_item("Host/MacOSX/Version");
  if (isnull(os))
  {
    num = split(array[3], sep:".", keep:FALSE);
    os = "Mac OS X 10." + string(int(num[0]) - 4) + "." + num[1];
  }
}
else if ( array[1] == "SecureOS" )
{
  os = get_kb_item("Host/SecureOS/release");
  if (isnull(os)) os = array[1] + " " + array[3];
  type = "firewall";
}
else if ( array[1] == "FreeBSD" )
{
  os = get_kb_item("Host/FreeBSD/release");
  if (!isnull(os) && "FreeBSD-" >< os)
    os = str_replace(find:"FreeBSD-", replace:"FreeBSD ", string:os);
  else
    os = array[1] + " " + array[3];
}
else if ( array[1] == "NetBSD" )
{
  os = "NetBSD";
  match = pregmatch(pattern:"^NetBSD .+ NetBSD ([0-9]+[0-9.]+) .+ ([^ ]+)$", string:uname);
  if (!isnull(match)) os += " " + match[1] + " (" + chomp(match[2]) + ")";
}
else if (array[1] == "OpenBSD")
{
  os = get_kb_item("Host/OpenBSD/release");
  if (!isnull(os) && "OpenBSD-" >< os)
    os = str_replace(find:"OpenBSD-", replace:"OpenBSD ", string:os);
  else
    os = array[1] + " " + array[3];
}
else if ( array[1] == "SunOS" )
{
  num = split(array[3], sep:".", keep:FALSE);
  if (int(num[1]) >= 7) os = "Solaris " + num[1];
  else os = "Solaris 2." + num[1];
  if ( "sparc" >< uname ) os += " (sparc)";
  else if ( "i386" >< uname ) os += " (i386)";
}
else if ( array[1] == "AIX" )
{
  # AIX servername 3 5 000B8AC4D600
  os = "AIX " + array[4] + "." + array[3];

  oslevel = get_kb_item("Host/AIX/oslevel");
  if (oslevel)
  {
    match = pregmatch(pattern:"^([0-9][0-9][0-9][0-9])-([0-9][0-9])$", string:oslevel);
    if (!isnull(match)) os += " TL " + int(match[2]);
  }

  oslevelsp = get_kb_item("Host/AIX/oslevelsp");
  if (oslevelsp)
  {
    match = pregmatch(pattern:"^([0-9][0-9][0-9][0-9])-([0-9][0-9])-([0-9][0-9])-([0-9][0-9][0-9][0-9])$", string:oslevelsp);
    if (!isnull(match)) 
    {
      if (" TL " >!< os) os += " TL " + int(match[2]);
      os += " SP " + int(match[3]);
    }
  }
}
else if ( array[1] == "ZscalerOS" )
{
  os = "Zscaler";
  type = "firewall";
}
else if ( array[1] == "Isilon" )
{
  os = "Isilon OneFS";
  type = "embedded";
}
else if ( array[1] =~ "^(CYGWIN|MINGW32)" )
{
  os = 'Microsoft Windows';
  confidence = 30;
}
else if (array[1] == "JUNOS" )
{
  os = "Juniper Junos Version " + array[3];
}
else if (array[1] == "Haiku" )
{
  os = "Haiku OS";
}
else if ( array[1] == "VMkernel" )
{
  type = "hypervisor";
  os = get_kb_item("Host/VMware/release");
  if (isnull(os))
  {
    os = array[1] + " " + array[3];
    confidence -= 35;  # Unknown VMkernel
  }
  else
  {
    confidence -= 1;
  }
}
##
#  Aruba ClearPass' banner populates the array variable, but
#   not with useful data.  Must inspect the uname variable instead.
##
else if (uname =~ "Policy Manager CLI" && uname =~ "Hewlett Packard Enterprise Development" )
{
  os = "Aruba ClearPass Policy Manager";
}
else if ( array[1] !~ "Linux|BSD|HP-UX|AIX|SunOS|Darwin|Minix|SCO_SV|IRIX|DragonFly|Haiku|VMkernel" )
{
  os = array[1] + " " + array[3]; confidence -= 35; # Unknown OS or error when executing uname?
}
else
{
  os = array[1] + " " + array[3]; confidence -= 10;
}

set_kb_item(name:"Host/OS/uname", value:os);
set_kb_item(name:"Host/OS/uname/Confidence", value:confidence);
set_kb_item(name:"Host/OS/uname/Type", value:type);
