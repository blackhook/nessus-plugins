#TRUSTED 1f197913c20de1f081206ffafddbf72d331b97f1c004dec7669b57a786a638064493f89d1d04238e99c4351b84dc61d4e245a451946294a78de75a676310dc73bddf8215998c4d025900bacc46e2d011ca8b13978af6bf49bc460c0041f0d57fc3b62b936693c283b516247ae77aa7c67fbc4ddce6c6a4bd8d470ab478605f0b08898bdae4835d33cd4e70921828f3521b51ff5333eae3d0aae563c8911bfe2732932e0d65a9ec1ea6fa1de0e603e6df40c70b17c93d0f63c15902d19f819c3980aa56cd553478ebbf58c25fc9c5b9c6c5165bfc5b257973e9a428b48afaea6f11ebc54fcfd52bf72e2d9737ea09c1be7624851ea67bb7159fcabe97f9a0333ff064fe8326c1a415a3d5a883894b8644b8cca8ae9d28c63aadff1b4ea13e91196393c6ebc028353134179851bbcf0e20723b58e1f83a1431f35aacc883b122a965c4f42399533cf49b9acd74bf80753ee9fd1f70fef15db1f12d5ac913b729aab1adea05241918051865bde8bde976ab28dfd29038d0813767b83c6466c4cf19bf3fc9f2b2f45c05ca4783efbb2eab05cadd1755809a3934bda2706aeaf0a1210edd962fec422e5dfb71f27987c83abdcaa34e29f3c4b1e27ae3fdaeac2b6d3536a5a661379531cad83cd2a107edf3914bf1dc96ece8cfb08091261075c88e4769dc8f56acc2ab7fd9525449571d488f66375703d51dcc700600d177f9593f59
#TRUST-RSA-SHA256 80e31cd78771f24e19e5a56b50a0c84d301bb34a9a887edb1a4dd09fa3aa0dcc4fe33c7ae1bbe23eaa8a64ea6652fa5c7d029f096b00338399a5c804d6668b467def02f6ea996980f63d3cf950926081138df97f5fcab4a023085be750fe3d45fa2f42bc5ac85132d9d7d4f2aa0590d3ef3c442b31a607c6cc019149feaafe0b2043a76906488670d4bcec1048f3544eba1a05d7b354b4b8a772459d20d40f71c847c3da8f4963bf429d269d5e02761999db5c94c604aa153749deb6ddbe0d68688c8715b5aca8dd8ab42b0b023b487d9b264f18669299afc505904f9bbf9dd3812582f9e1f9862c9f1659100f6533b241c3cec3fdc65f617a2b35683e9b7a8a4db95194caa59c5dcbee859c98e4f248d8316f7343612b9a9c13ed0571c2b9bc39e00ee561fd34b97d77202b9d35142bdd8d5b0ee5510c0fbd695cb58087d93f80ab01ea2212d8adaf8f9d84cdd6a54717a07ce0ba414f9d89d072a340bc5231dfb1578f07d9ff439676848a0388a22029606b0ae1e297502cf459dde992e0d14c8dc4297d30e2e4caff03c3fa8b50c365835c65cae62d6a3528a402fa9cff21c39a0864c450ed1dd252933a9fc4fb727309952c1687caec8d176aa4c8cf8197244ce78f9857807297934748c643655cbbc3ced216a6a8e7df3c670820943080981ff34ecccd044a35be0e4483ef8f768af16d549f6113861ae7e6cdf5b652c4
#
# (C) Tenable Network Security, Inc.
#


if (!defined_func("bn_random")) exit(0);


include("compat.inc");


if (description)
{
  script_id(58812);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/21");

  script_name(english:"Mac OS X OSX/Sabpab Trojan Detection");
  script_summary(english:"Checks for evidence of Sabpab");

  script_set_attribute(attribute:"synopsis", value:"The remote Mac OS X host appears to have been compromised.");
  script_set_attribute(attribute:"description", value:
"Using the supplied credentials, Nessus has found evidence that the
remote Mac OS X host has been compromised by a Trojan in the
OSX/Sabpab (alternatively known as OSX/Sabpub) family of Trojans.

OSX/Sabpab is typically installed by means of a malicious Word
document that exploits a stack-based buffer overflow in Word
(CVE-2009-0563). Once installed, it opens a backdoor for a remote
attacker to upload or download files, take screenshots, and run
arbitrary commands.");
  # http://www.sophos.com/en-us/threat-center/threat-analyses/viruses-and-spyware/OSX~Sabpab-A/detailed-analysis.aspx
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?2fbcf878");
  script_set_attribute(attribute:"solution", value:"Restore the system from a known set of good backups.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_attribute(attribute:"cvss_score_source", value:"manual");
  script_set_attribute(attribute:"cvss_score_rationale", value:"Tenable research analyzed the issue and assigned a score for it.");

  script_set_attribute(attribute:"plugin_publication_date", value:"2012/04/20");

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

homes = get_users_homes();

dbg::detailed_log(lvl:1, msg:'get_users_homes',
  msg_details:{
    'users home path':{'lvl':1, 'value':homes}
    }
);

if (isnull(homes)) exit(1, "Failed to get list of users' home directories.");

report = "";
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

  cmd1 = strcat('ls "', home, '"/Library/Preferences');
  cmd2 = strcat('ls "', home, '"/Library/LaunchAgents');
  res = exec_cmds(cmds:make_list(cmd1, cmd2));
  if (!isnull(res))
  {
    if (strlen(res[cmd1]) && "com.apple.PubSabAgent.pfile" >< res[cmd1])
      report += '\n  User : ' + user +
                '\n  File : ' +  home + '/Library/Preferences/com.apple.PubSabAgent.plist';

    if (strlen(res[cmd2]) && "com.apple.PubSabAgent.plist" >< res[cmd2])
      report += '\n  User : ' + user +
                '\n  File : ' +  home + '/Library/LaunchAgents/com.apple.PubSabAgent.plist';
  }
}
if (!report) exit(0, "No evidence of OSX/Sabpab was found.");


if (report_verbosity > 0) security_hole(port:0, extra:report);
else security_hole(0);