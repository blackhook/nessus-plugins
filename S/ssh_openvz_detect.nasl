#TRUSTED 69322b810dfe36e67c2d78374ddd9bba1b61dfaab5c9bb1b102a077cae0188229d5fa25809b2e991ec7038a59ff808540b0795a0a70919361bbfab70c67c1630c5260713a0ea9b6851ce17a623c96b17bbd05d132fbc5f87ee8ea11c3ffb7041fc70ed6d687ed68d3f7e2073e781fa89b89a062b4faedd46b16833d0d20329ad72a66a2ab185f7d199d64aa37937d130908553f4d83ffd8c16797f7b5abb06768b147cbd0f18197d23901f341808dc2bfb80542487d8620ed65986228bbdfb8d45f34e45fb883913d6e9c1f822a12814fee2268aae511c519fddb351317e12f02975289ec3bfa3a351b32e5ca2d342333629d050ffef05b13b083e047b99e65c6d5f33d7bf4caeb594c47c64973cf0229015236e2e0b072b66b28aa1f7f935b74848d7e610ca6bf496878c48ffa7d43f65767fe8e508dc189c8c77a715a5ae3670acfe638b93b3e7c4d8967753f7ee0bd1bb917d90cd65ea0dfd5eb481b16d15ee2c9924ed3baab4056cf3eee7d2385d734a0eb85fb3acf989979ac63a8cc032e73d0fb9a053f0b008187da3d56cdee9284c17d65b02479937eac390f0acc5e8bbee5be824ad4773df8414b765ddcdbd626812cb580c636638d950ec8e878b8d1504d6c88836b9db225ae5f22ee2e7dec175cedfef36cdea187e17cd0cf611e7819845bd73230747887fab9242904a122197dbfc40fb20cb96987488eb65f71d
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if(description)
{
 script_id(51092);
 script_version("1.16");
 script_set_attribute(attribute:"plugin_modification_date", value:"2022/06/29");

 script_name(english:"OpenVZ Guest Detection");
 script_summary(english:"Determines if the remote OS is running in an OpenVZ container");

 script_set_attribute(attribute:"synopsis", value:
"The remote host seems to be an OpenVZ virtual machine." );
 script_set_attribute(attribute:"description", value:
"/proc/user_beancounters could be read.  This file provides
information to the guest operating system in OpenVZ containers." );
 script_set_attribute(attribute:"see_also", value: "http://wiki.openvz.org/Proc/user_beancounters");
 script_set_attribute(attribute:"see_also", value: "https://en.wikipedia.org/wiki/OpenVZ");
 script_set_attribute(attribute:"solution", value:
"Ensure that the host's configuration is in agreement with your
organization's security policy." );
 script_set_attribute(attribute:"risk_factor", value:"None" );
 script_set_attribute(attribute:"plugin_publication_date", value:"2010/12/09");
 script_set_attribute(attribute:"plugin_type", value:"local");
 script_set_attribute(attribute:"cpe", value:"cpe:/o:openvz:vzkernel");
 script_set_attribute(attribute:"asset_inventory", value:"True");
 script_set_attribute(attribute:"hardware_inventory", value:"True");
 script_set_attribute(attribute:"os_identification", value:"True");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2010-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");
 script_family(english:"Misc.");
 script_dependencies("ssh_settings.nasl", "ssh_get_info.nasl");
 exit(0);
}

include("misc_func.inc");
include("ssh_func.inc");
include("telnet_func.inc");
include("hostlevel_funcs.inc");


if(sshlib::get_support_level() >= sshlib::SSH_LIB_SUPPORTS_COMMANDS ||
    get_one_kb_item('HostLevelChecks/proto') == 'local')
  enable_ssh_wrappers();
else disable_ssh_wrappers();

if ( ! get_kb_item('HostLevelChecks/proto' ) ) exit(0, "No credentials to log into the remote host");


# We may support other protocols here
if ( islocalhost() )
{
 if ( ! defined_func("pread") ) exit(1, "'pread()' is not defined.");
 info_t = INFO_LOCAL;
}
else
{
 sock_g = ssh_open_connection();
 if (! sock_g) exit(1, "ssh_open_connection() failed.");
 info_t = INFO_SSH;
}

cmd = 'LC_ALL=C cat /proc/user_beancounters';
buf = info_send_cmd(cmd: cmd);
if (info_t == INFO_SSH) ssh_close_connection();

if ('uid' >< buf && 'resource' >< buf && 'held' >< buf && 'maxheld' >< buf &&
    egrep(string: buf, pattern: 
 '^[ \t]+uid[ \t]+resource[ \t]+held[ \t]+maxheld[ \t]+barrier[ \t]'))
{
  if ( strlen(buf) < 8192 &&
       "Verbose" >< get_kb_item("global_settings/report_verbosity") )
    security_note(port: 0, extra: '\n/proc/user_beancounters contains :\n\n' + buf);
  else
    security_note(port: 0);  
  exit(0);
}
else exit(0, "The host does not appear to be an OpenVZ Guest.");
