#TRUSTED 2df4ef4108c836795e4d1bc9d258641f13ae12ffaa37205fc83dbacc52edea2bd0737adcc7a877b2913a3006ca7f3073b52d71b0710d0e5f7a3a2e0476b4f51b73dac96ecec7d3d30635ffcb19c23ef671904232b08f9489cc9f9d056d1fa7cdeb62afec4c21ea479ebae0bd0e919e143421ddd271f4f3fee68d405128ce43f95c8c0da7ea8cb54ff1375a97d7d1505a7f041afb4062904bed2954ed5aef5069553397e5476963c69c095dcc7f59cbd0bee2379f1e72ef3dbb0e205a4189e340e25a6ccac501c940a0b5f167daf60945969f1f35036ddd7cf7043bb00d0c4ce7828a26ce298f4124e18d7542de268206adb7ce2f7978319c50ddbf07f5e8607e9df14284b0db27cab84a8f23710d17862f9fa3211798857f395ab4ff2e6a1e6cc3206baf61dd56b130cd4232b35e814da7e8636f09a97a1e538de5b513bc7cce3e5e9fd9d7d28e965a8ce3c1e3a32c980f81ff6848bddb5dbf73806a65ab583a62fa38418a56275997f25edd62ff82839c736d91188c19eb184edb3dc8b1b69335b645dcfb4e3c153f0df7707122f64d4f8a4fccfd6695abb2a5995edd833f6114d2bef17015b9f8568898790cd852fe3719c3966e2d616cb02908089ce862288a6850199aedc18312abecdac51d4190c76f508cdf6bc27d728db7e50af275ea1293eadea2090d7fa27db309400103955afc2b37d4932641efdcf4435153e411
#TRUST-RSA-SHA256 72bc60caadf464a39d494b04183062640a11aeb1da66247676eab273a74179c70e6fd1f7be8c288c3fc47bc35ee451b2389cebe4f7b890d20e2ba25c4166a3c3d8602ac982fd575f1d726409105b629539ea98ba463948f1f0379f9eb20a39059a056433afb075e28fcf19ea5897c6d7725fc653d3df3251e7dacb179159ee6b6ba3c841f9b8ac4989073c7eb3044800fcf529bc03392d088cbb9b0e820cbc111fd3aedd0d52d0f103406d00a56d291474adeac6f5744765de4502227f65b5d9a1113847ba0919ed0a37ef985bacfe82b5a7db85d76a77c7141cab66b29b21ba56680bb236a19801ce94eeb8d7090ff13e4043bd3dd433172f75b3dea078cdb3c1d7ef450c4a7b18af027224b874ba8e658620e10457c95254791c7817531827eb5e2e34711605befc582bbaba010bc7dd9bbe085c2470e019e3158694b6705a30c2a427685a496e2a4e01713ed46dd30cdf7d969d07fd40f6c6a98482bbfa5473193b1576730da63139f575a9e6977968aa098c110ca1f86c864086daf12610a0a3eb4e43ba2414c2f50c6c32512ecc85a143845e03373e344ca0c9ba5d4eafd61b8a528015b444350d9f8cff8d6258859eb62579af3afdb208e7558ee35bb4a77c0e446ee1a704030ef14e14be08493e6fed19352b18b454bc29cf6e204b0603a885eb39b5fed07eeb3222952363fc331a96b37dc0edde35311b0bf1115fa1
#
# (C) Tenable Network Security, Inc.
#

if (!defined_func("bn_random")) exit(0);
if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(95929);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/01");

  script_name(english:"macOS and Mac OS X User List Enumeration");
  script_summary(english:"Lists users on macOS and Mac OS hosts.");

  script_set_attribute(attribute:"synopsis", value:
"Nessus was able to enumerate local users on the remote host.");
  script_set_attribute(attribute:"description", value:
"Using the supplied credentials, Nessus was able to extract the member
list of the 'Admin' and 'Wheel' groups on the remote host. Members of
these groups have administrative access.");
  script_set_attribute(attribute:"solution", value:"None");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2016/12/19");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:apple:mac_os_x");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:apple:macos");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2016-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/MacOSX/Version");

  exit(0);
}

include('ssh_func.inc');
include('macosx_func.inc');
include('mac_dscl_output_parser.inc');
include('mac_accounts_object.inc');
include('mac_groups_object.inc');

if(sshlib::get_support_level() >= sshlib::SSH_LIB_SUPPORTS_COMMANDS ||
    get_one_kb_item('HostLevelChecks/proto') == 'local')
  enable_ssh_wrappers();
else disable_ssh_wrappers();

if (!get_kb_item("Host/local_checks_enabled")) exit(0, "Local checks are not enabled.");

var os = get_kb_item("Host/MacOSX/Version");
if (!os) exit(0, "The host does not appear to be running macOS or Mac OS X.");

var cmd = "/usr/bin/dscl . -readall /Groups GroupMembership GroupMembers GeneratedUID RecordName RealName PrimaryGroupID";
var dscl_groups = new('mac_dscl_output_parser', exec_cmd(cmd:cmd));

cmd = "/usr/bin/dscl . readall /Users accountPolicyData NFSHomeDirectory PrimaryGroupID RealName RecordName UniqueID UserShell GeneratedUID";
var dscl_users = new('mac_dscl_output_parser', exec_cmd(cmd:cmd));

dscl_users = dscl_users.dscl_obj_data;
dscl_groups = dscl_groups.dscl_obj_data;

if(len(dscl_groups) == 0 || len(dscl_users) == 0)
  exit(0, "Could not retrieve users or groups using dscl.");

var groups = new('mac_groups'), member, res;
var tmp_group_members = {};
foreach var dscl_group(dscl_groups)
{
  if(!groups.make_group(key:dscl_group.GeneratedUID[0]))
    continue;
  
  groups.set_name(dscl_group.RecordName[0]);
  
  if(!empty_or_null(dscl_group.GroupMembership))
    tmp_group_members[dscl_group.GeneratedUID[0]] = dscl_group.GroupMembership;
  
  if(!empty_or_null(dscl_group.RealName))
    groups.set_real_name(dscl_group.RealName[0]);

  if(!empty_or_null(dscl_group.PrimaryGroupID))
    groups.set_pgid(int(dscl_group.PrimaryGroupID[0]));

  foreach member(dscl_group.GroupMembers)
    groups.add_account_member(member);
}

var accounts = new('mac_accounts');
foreach var dscl_user(dscl_users)
{
  if(!accounts.make_account(key:dscl_user.GeneratedUID[0]))
    continue;
  
  accounts.set_name(dscl_user.RecordName[0]);
  accounts.set_uid(int(dscl_user.UniqueID[0]));
  
  if(!empty_or_null(dscl_user.RealName))
    accounts.set_real_name(dscl_user.RealName[0]);
  
  if(!empty_or_null(dscl_user.PrimaryGroupID))
    accounts.set_pgid(int(dscl_user.PrimaryGroupID[0]));
  
  if(!empty_or_null(dscl_user.NFSHomeDirectory))
    accounts.set_home_directory(dscl_user.NFSHomeDirectory[0]);
  
  if(!empty_or_null(dscl_user.UserShell))
    accounts.set_command_shell(dscl_user.UserShell[0]);
}

# Consolidate group membership data in both objects
foreach var group_guid(keys(groups.groups))
{
  groups.focus_group(key:group_guid);
  foreach member(tmp_group_members[group_guid])
    groups.add_account_member(accounts.get_account_guid_by_name(name:member));
  
  foreach member(groups.groups[group_guid].accountMembers)
  {
    accounts.focus_account(key:member);
    accounts.add_group_membership(group_guid);
  }
}

var user_groups, user_data, res_usr = '', info = '', info2 = '';
foreach var user(accounts.accounts)
{
  res_usr += '\n' + user.name;

  user_groups = '';
  user_data = '';
  
  foreach var group(user.groupMembership)
    user_groups += groups.groups[group].name + '\n         ';
  
  if(user_groups) 
    user_groups = strcat('Groups : ', chomp(trim(user_groups)), '\n');

  user_data = strcat('\n', "User   : ", data_protection::sanitize_user_enum(users:user.name), '\n', user_groups);

  if(user.name !~ "^_")
    info += user_data;
  else
    info2 += user_data;
}
set_kb_item(name:"Host/MacOSX/Users", value:res_usr);

groups.report();
accounts.report();

var report = strcat(
  '\n----------[ User Accounts ]----------\n', info, 
  '\n----------[ Service Accounts ]----------\n', info2
);
security_report_v4(severity:SECURITY_NOTE, port:0, extra:report);
