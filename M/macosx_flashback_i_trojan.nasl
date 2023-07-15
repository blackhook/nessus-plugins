#TRUSTED 1d8696965699c0b331525b69bd9892400e3514356831c18db4924e07a13c85db4ccda1279078153a1a4757f58ecf1f1b99b6ca83ca36acf0813683038aa170872573f1eb40223bc77a0e24712dae6d3048ba2fc3be051fd71fe44fbf519e6ef3ffe3daf9ab924bc1b3588b11596e16b8b9b100e059c451cbf8d9414295d9277d80047c0e8683767c6dd3120e2ee38ffe0db40a8d627167525273836ae30250c4d6c531d5d8a71082e850d8c8d1a3b1d4dc7955d9f51a174cf7df05846de3fd8c1bc96f67bd04fe87258180f483da9b99f00e570dbd318899eb85ce763518541813b9f759982f33865f0d382127d40a011bf0a447da09fd2db6665ee896a8690141ad9cb99477ae185335081222dacf701db7bd3cc1ef831e960c28d66457f21e23ebeb0ac938e2649f311749c442751b00cf30b485d194edf6d01a5ba7c3dc90ab18903c8ba1c1575cc5df7b946f764c17863eb9da27c1efcd2c6be13f9bf771b486ae1a409649af7db9c6f74073332d53f9113e19ea2b536df286696a8bd3164dd1b7e54d11a1c9d8e233c2ade15e04a3e546e4c8b19236f065ba1b97da4cee2f4e234ad4dce58f851532991d652f8acce379b950d1ea26ae8af5bfed0dbd0dc178d0baf2fbf6dbaec1882ba42dfb3ebd8df9852bb26e6319fbe744ccd72533225a1cfd3872a1ae267b59090efe102bae393f07c49b19fa2516acba3db00d80
#TRUST-RSA-SHA256 3530ebfe551062a2548f1753735b7b6b61365d8abef445b7082ec4dad99600c21acdb73279c0c65a8ea208131ff1d6d28bb1dca3750500230a4d6f322aefbf424d88be6f5f5b377b97709d1d71586702c260b69ad18f33bf2af846628944a1ade9b8b5e8bc425b9d78a501310bd8d187abd095ba833120540f01f45760c8917ec93f39bafcb4f0174ed9b082aa505665a0f417ed526836a3e5a2506e4f68b7bb3810445782eb4b539f359adde6a7b842461a85dee5d22c2c6c956a9483e08bcb505747b531177a5697b935e3d2396aa9a264400df891054f18d7ff41fdfc795ba7af8fb489eaae40074329537fa16b188e85c02794f337d255e6ec9ae49908089077b1ac0862fe9997527c72d8d43e9b07eb02118a2b7786e25fad2377ab0ed70671e179398c25f17c9951ffa6664f6d23ac9b1c550b3c040964c82f67593ab7fcb88430cf5bdee63e1ccb2a9ca33438ee2c235c8dce7df5f8642a6f99a6fe51bc7cc8ee33f1e9b2609b5f5fa639e4271c518c86a22c42d0554d24940cad2c17194b0537094b1693e8ca8fe56a3de228f52674dcc0fc5b38f3b8550ffc2d30622599f566a64e2f8f7206f2c31619f7a5d80458e0c23f3a33afdd3c441d8ea7965cb5d336f3ba29a9b8d6cf9b8daf802fecec712dee8b9a9708edcc7d1552b3aaf93f09534e0f3625b88e521fcbe24a3ffd9e39c3c6e73b36450b6ab1e665ce36
#
# (C) Tenable Network Security, Inc.
#


if (!defined_func("bn_random")) exit(0);


include("compat.inc");


if (description)
{
  script_id(58619);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/21");

  script_name(english:"Mac OS X OSX/Flashback Trojan Detection");
  script_summary(english:"Checks for evidence of Flashback");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote Mac OS X host appears to have been compromised."
  );
  script_set_attribute(
    attribute:"description",
    value:
"Using the supplied credentials, Nessus has found evidence that the
remote Mac OS X host has been compromised by a trojan in the
OSX/Flashback family of trojans. 

The software is typically installed by means of a malicious Java
applet or Flash Player installer.  Depending on the variant, the
trojan may disable antivirus, inject a binary into every application
launched by the user, or modifies the contents of certain web pages
based on configuration information retrieved from a remote server."
  );
  script_set_attribute(
    attribute:"see_also", 
    value:"http://www.f-secure.com/v-descs/trojan-downloader_osx_flashback_a.shtml"
  );
  script_set_attribute(
    attribute:"see_also", 
    value:"http://www.f-secure.com/v-descs/trojan-downloader_osx_flashback_b.shtml"
  );
  script_set_attribute(
    attribute:"see_also", 
    value:"http://www.f-secure.com/v-descs/trojan-downloader_osx_flashback_c.shtml"
  );
  script_set_attribute(
    attribute:"see_also", 
    value:"http://www.f-secure.com/v-descs/trojan-downloader_osx_flashback_i.shtml"
  );
  script_set_attribute(
    attribute:"see_also", 
    value:"http://www.f-secure.com/v-descs/trojan-downloader_osx_flashback_k.shtml"
  );
  # http://www.intego.com/mac-security-blog/new-flashback-variant-continues-java-attack-installs-without-password/
  script_set_attribute(
    attribute:"see_also", 
    value:"http://www.nessus.org/u?7f51a6ed"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Restore the system from a known set of good backups."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_attribute(attribute:"cvss_score_source", value:"manual");
  script_set_attribute(attribute:"cvss_score_rationale", value:"Tenable research analyzed the issue and assigned a score for it.");


  script_set_attribute(attribute:"plugin_publication_date", value:"2012/04/06");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2012-2022 Tenable Network Security, Inc.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/MacOSX/Version");

  exit(0);
}

include('ssh_func.inc');
include('macosx_func.inc');
include('debug.inc');
include('command_builder.inc');

if(sshlib::get_support_level() >= sshlib::SSH_LIB_SUPPORTS_COMMANDS ||
    get_one_kb_item('HostLevelChecks/proto') == 'local')
  enable_ssh_wrappers();
else disable_ssh_wrappers();

if (!get_kb_item("Host/local_checks_enabled")) exit(0, "Local checks are not enabled.");

os = get_kb_item("Host/MacOSX/Version");
if (!os) exit(0, "The host does not appear to be running Mac OS X.");


report = "";
foreach app (make_list("Safari", "Firefox"))
{
  cmd = strcat("defaults read /Applications/", app, ".app/Contents/Info LSEnvironment");
  res = exec_cmd(cmd:cmd);
  if (strlen(res) && "DYLD_INSERT_LIBRARIES" >< res)
  {
    libs = egrep(pattern:"DYLD_INSERT_LIBRARIES", string:res);
    libs = str_replace(find:'\n', replace:'\n                          ', string:libs);
    report += '\n  Command               : ' + cmd +
              '\n  DYLD_INSERT_LIBRARIES : ' + libs;
  }
}

homes = get_users_homes();

dbg::detailed_log(lvl:1, msg:'get_users_homes',
  msg_details:{
    'users home path':{'lvl':1, 'value':homes}
    }
);

if (isnull(homes)) exit(1, "Failed to get list of users' home directories.");

foreach user (sort(keys(homes)))
{
  home = homes[user];
  # Check path for unexpected chars
  if (!command_builder::validate_no_injection_denylist(home))
  {
    dbg::detailed_log(lvl:1, msg:'Exiting due to injection attempt in users home dir',
        msg_details:{
          'home dir':{'lvl':1, 'value':home}
        }
    );
    exit(1, 'Unexpected characters in current user home directory: ' + obj_rep(home));
  }

  if (home == "/var/empty" || home == "/dev/null") continue;

  cmd1 = strcat('defaults read "', home, '"/.MacOSX/environment DYLD_INSERT_LIBRARIES');
  cmd2 = strcat('ls "', home, '"/Library/LaunchAgents');
  cmd3 = strcat('ls -a1 "', home, '"/');
  res = exec_cmds(cmds:make_list(cmd1, cmd2, cmd3));
  if (!isnull(res))
  {
    if (
      strlen(res[cmd1]) &&
      "DYLD_INSERT_LIBRARIES" >< res[cmd1] &&
      "DYLD_INSERT_LIBRARIES) does not exist" >!< res[cmd1]
    )
    {
      libs = egrep(pattern:"DYLD_INSERT_LIBRARIES", string:res);
      libs = str_replace(find:'\n', replace:'\n                          ', string:libs);
      report += '\n  User                  : ' + user +
                '\n  Command               : ' + cmd +
                '\n  DYLD_INSERT_LIBRARIES : ' + libs;

    }
    if (strlen(res[cmd2]) && "com.java.update.plist" >< res[cmd2])
    {
      report += '\n  User : ' + user +
                '\n  File : ' +  home + '/Library/LaunchAgents/com.java.update.plist';
    }
    if (strlen(res[cmd3]) && res[cmd3] =~ "^\.jupdate$")
    {
      report += '\n  User : ' + user +
                '\n  File : ' +  home + '/.jupdate';
    }
  }
}


if (report)
{
  if (report_verbosity > 0) security_hole(port:0, extra:report);
  else security_hole(0);
  exit(0);
}

exit(0, "No evidence of OSX/Flashback was found.");

