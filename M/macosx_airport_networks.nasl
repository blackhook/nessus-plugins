#TRUSTED 22291ebb46d5a79f388a341e3bd2e07dd412658929d79891d1725fd6cb9d8fd56ca4848b54c56e101a15a92d67bb09b1ba362d6161c49919cec086089e0d2e48f04c4440583883a6a6b7c2d8b619fc9865f3c099634512495ec9e775e3f46a37851f913e44c55e43efdff21bfb16ea715c8b9398bfec6008c1fb55184b90054c56843c50d0867ae6292ae191ca491d002bd4667d3c9260cc4e8ce230c48479dcabb366afbdd63bded4286400c73a8feddd223b22064252f89bcf11d47c4a509eefcf07d8e427e3808f6ff7b521d187fcaece9275fe44a9356917d47bcd5f5697b5e20ee85bbfb2d71eea04b0c43ffa8721f2faa214283582436cdc8670c09d7018d72c645f6061e8fa352dbbd0692d8fc2d99a34185b7ed2248551e99aa5494bef316c7643d89a92d53240b9326072fdd1b116dabee8f5ff3aee94a98d8b803bc13e0549896ad9a8b183228e501acc78d8baff26f4c0c9b9ef178eec0c42fa2ecaf5832b22f13596526aedc79f1cf8b6b076b72b996500d73e2928c15ce70767acb90fb3b74d272ad5485ad37e03f564d3ce3968853b698417a6caecfc10308cdebe4977e26b26ea245467ef38a10d91d6dc9c5e77294fc9cf8e7e7f6ea6b638d7f10a420465b94d50d8ea48fa7937ad1c75d33492cd54906dd54deeaffe37e2059e60d637c2900646949f571c6de103e54bc568d426af760b48b7acc8ab044f
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(63340);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/06/29");

  script_name(english:"Mac OS X Wireless Networks List");

  script_set_attribute(attribute:"synopsis", value:"The remote host has connected to wireless networks in the past.");
  script_set_attribute(attribute:"description", value:
"Using the supplied credentials, it is possible to extract the list of
networks to which the remote host has connected in the past.");
  script_set_attribute(attribute:"solution", value:
"Ensure that use of Wi-Fi networks is done in accordance to your
organization's acceptable use and security policies.");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2012/12/27");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:apple:mac_os_x");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2012-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/MacOSX/Version");

  exit(0);
}


include("ssh_func.inc");
include("macosx_func.inc");


if(sshlib::get_support_level() >= sshlib::SSH_LIB_SUPPORTS_COMMANDS ||
    get_one_kb_item('HostLevelChecks/proto') == 'local')
  enable_ssh_wrappers();
else disable_ssh_wrappers();

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

os = get_kb_item("Host/MacOSX/Version");
if (!os) audit(AUDIT_OS_NOT, "Mac OS X"); 

report = NULL;

preferences = [ 'KnownNetworks', 'RememberedNetworks' ];

foreach preference (preferences)
{
  cmd = strcat('defaults read /Library/Preferences/SystemConfiguration/com.apple.airport.preferences ', preference, ' | egrep "(SSIDString|LastConnected|SecurityType)"');

  res = exec_cmd(cmd:cmd);
  if ( "SSIDString =" >!< res ) continue;
  array = split(res, keep:FALSE);
  flag = 0;
  foreach line ( array )
  {
   if ( "LastConnected" >< line )
    date = str_replace(find:'"', replace:"", string:ereg_replace(pattern:".*LastConnected = (.*);$", string:line, replace:"\1"));
   else if ( "SecurityType" >< line )
   {
    security = str_replace(find:'"', replace:"", string:ereg_replace(pattern:".*SecurityType = (.*);$", string:line, replace:"\1"));
    flag = 1;
   }
   else if ( "SSIDString" >< line )
   {
    network = str_replace(find:'"', replace:"", string:ereg_replace(pattern:".*SSIDString = (.*);$", string:line, replace:"\1"));
    flag = 1;
   }

   if( (strlen(network) > 0 && strlen(security) > 0) ||
       (strlen(date) > 0 && strlen(network) > 0 && flag == 0 ) )  # In case there's no "SecurityType" associated to the remote network
   {
    report += '-  Network name : ' + network;
    if ( flag != 0 )
    {
     if ( strlen(date) ) report += '\n   Last connected : ' + date;
     else report += '\n   Last connected : N/A';
     date = NULL;
    }
    if ( strlen(security) )
    {
     report += '\n   Security: ' + security;
    }
    network = security = NULL;
    flag = 0;
    report += '\n\n';
   }
  }
  break;
}

if (empty_or_null(report))
  exit(0, "Could not extract the list of Wi-Fi networks.");

security_report_v4(port:0, extra:report, severity:SECURITY_NOTE);

