#TRUSTED 7c9120c5ca89db64dcbede2cdac6e7f4e52333b7b6b5982d30409c3a7d33b2b9097ccc3eaddebff5a89ae5274c791849f24c1b7f9fbf1e303c5792e89c7ad1c2f69f822f4a38ae67f11bb938ca31d074fa5243d9785e0433a739cde1c4506cb6a375d7c036e7c1150ad4d1603ccfb1fda27d1959d7fc4d692146f8d47d964ee73c102da05868cb46a69dd1a44a2accce3fc61cdf60f0e3585370c86362fd2547dd49ce3ea52e57c48c3bef3d819cbd269ce06eab9856141d1402c2794cc846d4169f12583f40f4ffb4591957a42fd290e81b9adf8ef648eda9a476cf4551b4b6d8ad2fe0cf253d92668485f645df3cc0ea5fc1c2a0b39c28d24be5a5e0da5dca12c7144c6cbb7dc6f5e444dd0c4f1987a9d2df9843490895986774a05e646477853ac17f0112c34bc26ce71a65b0997633c49bd970428c60fc680ef0986174749d5e963bef67d859148cf86a957fb62568d8d007b055c2561a622a4388c4f7e07ca9a32ae62e03225155533c0e12d91c87469b64bca9d75c17e3171e6ab486aa453da89328239fe809f697f29525f5d2f6e2a1742f19bf3b5fdd5a8a2d29d27e2c14eeabe2d212444a935912e147d085618ded948e2217d12c7a9d39a00bca531b1ba98dabab575011b7006eb89a1cf0f8d82ac447ea2a7a836e7ad663b5625c3a3776d3d32d68e6ecc4e6590bbed072b3cbcb1b0ef76ddeef10b42cd15abca4
#TRUST-RSA-SHA256 5374851b93096fcd769df31de6e245910bdaa35373b66749188afb66a2958b9ceaaae197016d84dd2b652e683b606a00c9a85cb12bee3f1465529df3fa1613f5eed5e597d458d1412ec2f68a5c5ea3b7b6946c71859d93d343a2150365cfffe472457ff64c18e095f93564dd90cde788da2c43351450b1ded9d93ff39a0c31e09924774599b407e254c6808b5b5207d3a95b30b877372479a5ced61827c0333f5da3789e5f026560dc2a249ea3415d1a07c791149cc5a07311bb2a67a10762685f05da4a319f8103a8942f3d0e91fd1428b00a39a0e4fb5992b69d92aebcf24cebcb8f1918140f01306885d01f08c34d93c5aad6410dde05636fcfbc5394de603421abd38716090f090dd079e110a552f678835408c461f1733df3c5f20b96ef5a87d12a4dd1e3bd21e289b7e123d5373c4f57f96f1d6a6bbec3d16c47deefeefd2c17a69a64e4e31e6a15cd5ab062452a7d069c61b2b6f9d2d63cb9ba2253a2397b81c482f8f32317e6c3fb06fe29de6c56ead726abc0e3b788966a7003aed726d5018f210eb8f42d5a7d675151d521e60e2c6d92c365c5d0113255bd3507c2f3d8896d8ed0ad365be82de8af4f54acb476ecc45da33e74e64161703ff33bf40f4526c825132c128dd4a171521faa1ce5249477df4a3d88435196571ad4164c655acc17faac4d7b6a03c5bcbe9c900c1fe919501b4a5c698b5d15efbc059dc7
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(100128);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/21");


  script_name(english:"HandBrake OSX/Proton.B Trojan Backdoor (macOS)");
  script_summary(english:"Checks the HandBrake install for a trojanized application.");

  script_set_attribute(attribute:"synopsis", value:
"An application installed on the remote macOS or Mac OS X host is
affected by a trojan.");
  script_set_attribute(attribute:"description", value:
"According to its binary checksum, the version of HandBrake installed
on the remote macOS or Mac OS X host is affected by the OSX/Proton.B
trojan backdoor. HandBrake was briefly distributed with the trojan due
to a compromised mirror hosting the software. An unauthenticated,
remote attacker can exploit this to exfiltrate sensitive information,
download malicious files, and execute arbitrary code.");
  script_set_attribute(attribute:"see_also", value:"https://forum.handbrake.fr/viewtopic.php?f=33&t=36364");
  script_set_attribute(attribute:"solution", value:
"To remove the infected application, open the Terminal application and
run the following commands :

  - launchctl unload ~/Library/LaunchAgents/fr.handbrake.activity_agent.plist
  - rm -rf ~/Library/RenderFiles/activity_agent.app

Remove the proton.zip archive from the ~/Library/VideoFrameworks/
folder if it exists, and remove any HandBrake.app installs.
Additionally, it is strongly recommended to change all the passwords
that reside in your OSX KeyChain and browser password stores.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"manual");
  script_set_attribute(attribute:"cvss_score_rationale", value:"Score based on an in depth analysis by Tenable.");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/05/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/05/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/05/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/a:handbrake:handbrake");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2017-2022 Tenable Network Security, Inc.");

  script_dependencies("macosx_handbrake_installed.nbin");
  script_require_keys("installed_sw/HandBrake", "Host/MacOSX/Version", "Host/local_checks_enabled");

  exit(0);
}

include('audit.inc');
include('global_settings.inc');
include('misc_func.inc');
include('install_func.inc');
include('ssh_func.inc');
include('macosx_func.inc');
include('ssh_globals.inc');
include('command_builder.inc');

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

get_kb_item_or_exit("Host/MacOSX/Version");

app_name = "HandBrake";
install = get_single_install(app_name:app_name, exit_if_unknown_ver:TRUE);
version = install['version'];
path    = install['path'];
dbg::detailed_log(lvl:1, msg:'Install path',
  msg_details:{
    'path':{'lvl':1, 'value':path}
    }
);
# Check path for unexpected chars
if (!command_builder::validate_no_injection_denylist(path))
{
  dbg::detailed_log(lvl:1, msg:'Exiting due to injection attempt in HandBrake install path',
      msg_details:{
        'install path':{'lvl':1, 'value':path}
      }
  );
  exit(1, 'Unexpected characters in HandBrake install path: ' + obj_rep(path));
}

homes = get_users_homes();
if (empty_or_null(homes)) exit(1, "Failed to get list of users' home directories.");
dbg::detailed_log(lvl:1, msg:'User homes',
  msg_details:{
    'homes':{'lvl':1, 'value':homes}
    }
);

vuln = FALSE;
report = "";
# Check HandBrake binary's checksum for infected checksum
cmd = 'shasum -a 1 ' + path + '/Contents/MacOS/HandBrake';
hash = exec_cmd(cmd:cmd);

if (hash && hash =~ 'a8ea82ee767091098b0e275a80d25d3bc79e0cea')
{
  vuln = TRUE;

  report +=
    '\n  Path              : ' + path +
    '\n  Installed version : ' + version +
    '\n  The version of HandBrake installed on the remote host is known' +
    '\n  to contain a trojan.';
}

# Check each user's home directory for files added for malware
# persistence:
#   ~/Library/RenderFiles/activity_agent.app
#   ~/Library/LaunchAgents/fr.handbrake.activity_agent.plist
foreach user (sort(keys(homes)))
{
  home = homes[user];
  if (!command_builder::validate_no_injection_denylist(home))
  {
    dbg::detailed_log(lvl:1, msg:'Exiting due to injection attempt in a user\'s home directory',
        msg_details:{
          'home dir':{'lvl':1, 'value':home}
        }
    );
    exit(1, 'Unexpected characters in a user\'s home directory: ' + obj_rep(home));
  }
  if (home == "/var/empty" || home == "/dev/null") continue;

  cmd1 = strcat('ls "', home, '"/Library/RenderFiles');
  cmd2 = strcat('ls "', home, '"/Library/LaunchAgents');
  res = exec_cmds(cmds:make_list(cmd1, cmd2));

  if ("activity_agent.app" >< res[cmd1] ||
      "fr.handbrake.activity_agent.plist" >< res[cmd2])
  {
      vuln = TRUE;
      report += '\n\n  The following users have the infected files in their' +
                '\n  home directories :';
      if (strlen(res[cmd1]) && "activity_agent.app" >< res[cmd1])
      report += '\n    User : ' + user +
                '\n    File : ' + home + '/Library/RenderFiles/activity_agent.app';

      if (strlen(res[cmd2]) && "fr.handbrake.activity_agent.plist" >< res[cmd2])
      report += '\n    User : ' + user +
                '\n    File : ' + home + '/Library/LaunchAgents/fr.handbrake.activity_agent.plist';
  }
}

# Check for activity_agent in running processes
cmd = 'ps aux';
procs = exec_cmd(cmd:cmd);
if (strlen(procs) && "activity_agent" >< procs)
{
  vuln = TRUE;
  report += '\n\n  The activity_agent process is running on the system.';
}

if (vuln) security_report_v4(port:0, severity:SECURITY_HOLE, extra:report);
else audit(AUDIT_INST_PATH_NOT_VULN, app_name, version, path);
