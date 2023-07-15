#TRUSTED 3d4b14e3871cc55a377139f31f468aa569480296e687fb9438bf5bfcd84b7da87eb87e1d6c879a20fa65a3f3dab12dfe6ae6fa7549f03eee4a2797352b147ff8eac4e022d794bbf17f1ffe04ce8f49f8ce9ea767bf476d8f117aa72df5d840fccadf5e2dfeffb128c1fe89ae5f1aaf714f0f7c495c8935cb65aa6840d4e55b2d61a0850777b8ffada32d17849cf0fe88249c7b856cfe830eabc26ce7d689a609e2edd6ac8d8b31ffa1b478db1229bc45bd1f84a3ddc03d1108e0436bda982fc7f835e1c967a6e148248fd413dbc695b3680e6e9a69907e393fdeda7ab60c22f6bae8b6e445e90be88c682ccd7f2796febc1e7643a2262d714dd81ee90077c669144546980316dede5240fe8fe20359a2eeb625497fdaabae5af714ab3a24d8547e2a1374a0506599030e88170ba54633a7d7336ef75c7e2f00039338dbc0cc38c08603e91cbdb67880e6e8314b661237ebd19724f560d123089d8a102c251786893a371292643b14aa7cbac77079ed9366738bca56767c0e21e1ea6de9a16c9ebc0015260b8a5e86c9fc56169924eea04f9df03e70a6ff4c1cd776f9e96b0bd87387475da5cd520ad4b5b28679557ba1f1da6d5ebc4e7b0f239a2285ede74a6adca46f0343ecbdc18d7416bf5efbada1f411b441910ed07dcf2c6ee1b6ca5a7a2d5116b456385d5f3d8bb5fb3d0e34e0dece487a6a19f4c8d6031dbd452c0f79
#TRUST-RSA-SHA256 5b9c8140912ff1fe86bde529c2ca44b23e8b5c783a7efdf58cfb01760d4ff16959eb2321aef17b63eff61bce948500d92a81f2b5489e07b49e4f54ad4e609a4d8bb52db2eaacb6adb959146045ce9f3aa647e9758fd2da7a2f590e8cb809ddfb2ed57210d71df1f0023216de08fc55b886a9168b729779443daa67a7168a23cddedf78ad125bafdd5a7cea5f6cc11d8a975e6c51194a952f10b6bd8c25290fd83500cda7c918421c84cc40cc9f9a11d7406353a7eacfd7f56740b48bcf506441be37cc2966f09c1b92ebdb866105ee5ba854d59704ee3df6fd3c5e9766426d9fdf1d1f746c0102504b84179c3edc62ce5f03cc1397df6665863ec3b193a1732a1ff7c2e07de3d46cbb5d33d539cb4718f9e18e36bc4cb00f61390373f6e1087ec83f8c88f8e7a3fe1522a4dec6cced1384c0ca853217f99f2275a56d1edfb1bba5147c3f145ff07109653417260020d1261d35288a4ef720b08e0ed20395d7a9a92c40956c69c53610debaa98c8e939e3d618a2c34bd18379577723697b90ea9b92cd4a7ae02619a5e1c27488bda0ac6a1c95f81fb76683410f85193b46dbed785ee642acf455e5bbf7672c28c50bb35389e363796ab7c774ae3016401cb48b2620634781ffb18ec17095e37056d8563b0f85541d9557b95be5abdafd65c4fa32098240ccba2cd3f8dc7018541e00498bf0acd53040d5cf8ec993113de92e17c
#
# (C) Tenable Network Security, Inc.
#

if (!defined_func("bn_random")) exit(0);
if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(95928);
  script_version("1.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/02/28");

  script_name(english:"Linux User List Enumeration");
  script_summary(english:"Lists users on Linux host.");

  script_set_attribute(attribute:"synopsis", value:
"Nessus was able to enumerate local users and groups on the remote
host.");
  script_set_attribute(attribute:"description", value:
"Using the supplied credentials, Nessus was able to enumerate the local
users and groups on the remote host.");
  script_set_attribute(attribute:"solution", value:"None");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2016/12/19");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"agent", value:"unix");

  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"General");

  script_copyright(english:"This script is Copyright (C) 2016-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/uname");

  exit(0);
}

include("ssh_func.inc");
include("telnet_func.inc");
include("hostlevel_funcs.inc");
include("agent.inc");
include('linux_groups_object.inc');
include('linux_accounts_object.inc');

function create_account_object(uid, usr, home, shell, default_gid, &users)
{
  if(typeof(uid) != 'int') 
    return NULL;

  var gid, group_name;
  if(!structured_accounts.make_account(key:uid))
    return FALSE;
  
  structured_accounts.set_name(usr);
  structured_accounts.set_home_directory(home);
  structured_accounts.set_command_shell(shell);

  # Set default user group membership
  structured_accounts.add_group_membership(default_gid);
  structured_groups.focus_group(key:default_gid);
  structured_groups.add_group_membership(uid);

  foreach group_name(keys(users[usr]))
  {
    gid = structured_groups.get_gid_by_name(name:group_name);
    if(!gid) continue;

    structured_accounts.add_group_membership(gid);
    structured_groups.focus_group(key:gid);
    structured_groups.add_group_membership(uid);
  }
}

function create_group_object(gid, name)
{
  if(typeof(gid) != 'int') 
    return NULL;

  if(!structured_groups.group_exists(key:gid))
  {
    if(!structured_groups.make_group(key:gid))
      return FALSE;
  }
  else
  {
    structured_groups.focus_group(key:gid);
  }
  
  structured_groups.set_name(name);
  return TRUE;
}

if(sshlib::get_support_level() >= sshlib::SSH_LIB_SUPPORTS_COMMANDS ||
    get_one_kb_item('HostLevelChecks/proto') == 'local')
  enable_ssh_wrappers();
else disable_ssh_wrappers();

if (!get_kb_item("Host/local_checks_enabled")) exit(0, "Local checks are not enabled.");

var uname = get_kb_item_or_exit("Host/uname");
if ("Linux" >!< uname) audit(AUDIT_OS_NOT, "Linux");

# Decide transport for testing
if (islocalhost())
{
  if ( ! defined_func("pread") ) exit(1, "'pread()' is not defined.");
  info_t = INFO_LOCAL;
}
else
{
  sock_g = ssh_open_connection();
  if (!sock_g) audit(AUDIT_FN_FAIL, 'ssh_open_connection');
  info_t = INFO_SSH;
}

var cmd = "cat /etc/passwd";
var etcp = info_send_cmd(cmd:cmd);

cmd = "cat /etc/group";
var etcg = info_send_cmd(cmd:cmd);

cmd = "cat /etc/login.defs";
var etcl = info_send_cmd(cmd:cmd);

if (info_t == INFO_SSH) ssh_close_connection();

if("Permission denied" >< etcp || empty_or_null(etcp)) exit(0, "Could not read /etc/passwd.");

var structured_groups = new('linux_groups');
var structured_accounts = new('linux_accounts');

var checkuid = FALSE, uid_min, uid_max;
if("UID_MIN" >< etcl){
  var match = pregmatch(pattern:"UID_MIN\s+(\d+)\s+UID_MAX\s+(\d+)", string:join(split(etcl,keep:FALSE),sep:" "));
  if(!empty_or_null(match))
  {
    uid_min = int(match[1]);
    uid_max = int(match[2]);
  }
  checkuid = TRUE;
}

var users = make_array();
var groups = make_array();
var grp, user;
foreach grp (split(etcg, keep:FALSE))
{
  if(grp !~ "^[^:]+:[^:]*:[^:]*:[^:]*$") continue;
  grp = split(grp, sep:":", keep:FALSE);
  groups[grp[2]] = grp[0];

  create_group_object(gid:int(grp[2]), name:grp[0]);

  foreach user (split(grp[3], sep:"," , keep:FALSE))
  {
    if(empty_or_null(users[user])) users[user] = make_array(grp[0], TRUE);
    else users[user][grp[0]] = TRUE;
  }
}

var report = '';
var report_usr = '';
var report_sys = '';
var usr_acct = FALSE;

var line, usr, uid, home, shell, gid;
foreach line (split(etcp, keep:FALSE))
{
  if(line !~ "^[^:]+:[^:]*:[^:]*:[^:]*:[^:]*:[^:]*:[^:]*$") continue;
  usr = split(line, sep:":", keep:FALSE);
  uid = int(usr[2]);
  home = usr[5];
  shell = usr[6];
  gid = int(usr[3]);
  usr = usr[0];

  create_account_object(uid:uid, usr:usr, home:home, shell:shell, default_gid:gid, users:users);

  if(checkuid && uid >= uid_min && uid <= uid_max) usr_acct = TRUE;
  # add default group in case it wasn't already added
  if(empty_or_null(users[usr])) users[usr] = make_array(groups[gid], TRUE);
  else users[usr][groups[gid]] = TRUE;
  if(checkuid)
  {
    if(usr_acct)
    {
      usr = data_protection::sanitize_user_enum(users:usr);
      report_usr += '\n';
      report_usr += join( "User         : " + usr, 
                          "Home folder  : " + home, 
                          "Start script : " + shell,
                          "Groups       : " + join(keys(users[usr]), sep:'\n               '),
                          sep:'\n');
      report_usr += '\n';
    }
    else
    {
      report_sys += '\n'; 
      report_sys += join( "User         : " + usr, 
                          "Home folder  : " + home, 
                          "Start script : " + shell,
                          "Groups       : " + join(keys(users[usr]), sep:'\n               '),
                          sep:'\n');
      report_sys += '\n';
    }

  }
  else
  {
    usr = data_protection::sanitize_user_enum(users:usr);
    report += '\n';
    report += join( "User         : " + usr, 
                  "Home folder  : " + home, 
                  "Start script : " + shell,
                  "Groups       : " + join(keys(users[usr]), sep:'\n               '),
                  sep:'\n');
    report += '\n';   
  }
  if(!empty_or_null(users[usr]))
    set_kb_item(name:"Host/Users/"+usr+"/Groups", value:join(keys(users[usr]), sep:'\n'));

}
set_kb_item(name:"Host/Users", value:join(keys(users), sep:'\n'));

if(checkuid) report = '\n' + 
                      "----------[ User Accounts ]----------" + 
                      '\n' +
                      report_usr +
                      '\n' +
                      "----------[ System Accounts ]----------" + 
                      '\n' +
                      report_sys +
                      '\n';

structured_groups.report();
structured_accounts.report();

security_report_v4(severity:SECURITY_NOTE, port:0, extra:report);
