#TRUSTED 55cc7c1b98b7e315ac6cf33093f747d6b1f41dddb3ae18d943784ccccc701a09484bb15b2ae9ccc27152e753bb69e96e64c5154ea970d054e340ffc6a0a3f857f9df1c30d8bab58c4e7f41daa3ee233a739ab658d237d5ce28f045dff1128fa1f8921d6f35142ef49e2f01731477fd5c1b0a128583ad03ffc271ce1a69e412f41be94ed7dd1dc6be94b734896ac1a9876babc8b2547fd22ca10aded02578ac366ee966d68cdf4821b9ba4e74f19372d8142babdc49702c18811a7937af8d53e847385d294a095cfcd2b1bb081ab9823d56ec318226d11b098ef6e8936f2c9b9fe9435b4c8c789da0689594564d825d1ef904971b44b6a29aa3a6f10132c1c6d2cfde1b0615e0f96359c5ebd660eb2141c977493a4a2be4d4297ddebf83aa2aa95897eae82a39246eb26de304a14dd46d15d9d62dc1b509b60c1d41cafc131d355f6a1a7478ebdc2d7141563cb7f3f972ff1681d1ed295d7c24d6c60691a65082b629e74792518dfbc06321b292038e31155300970c8f95febea733594df75b646bf6fa591062a140268b41a207a30bd55b44064faa36d559cdeb6c32cea0008848e5298e50e934e1acdbca8988ca5f949640ab5a1a864c65ee984bf9882358029738a612f0dda2acbec201c471ba50be0cc61f594c6075d1d5bdab060704b66fc4feb81dc08b8de04f48ee68e32a78feeb6793f8bcd15603e76638c6a679caf4
#
# (C) Tenable Network Security, Inc.
#

if (!defined_func("bn_random")) exit(0);
if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(60019);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/06/29");

  script_name(english:"Mac OS X Admin Group User List");
  script_summary(english:"Lists users that are in special groups.");

  script_set_attribute(attribute:"synopsis", value:
"There is at least one user in the 'Admin' group.");
  script_set_attribute(attribute:"description", value:
"Using the supplied credentials, Nessus was able to extract the member
list of the 'Admin' and 'Wheel' groups. Members of these groups have
administrative access to the remote system.");
  script_set_attribute(attribute:"solution", value:
"Verify that each member of the group should have this type of access.");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2012/07/18");

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

include("global_settings.inc");
include("misc_func.inc");
include("ssh_func.inc");
include("macosx_func.inc");
include("data_protection.inc");


if(sshlib::get_support_level() >= sshlib::SSH_LIB_SUPPORTS_COMMANDS ||
    get_one_kb_item('HostLevelChecks/proto') == 'local')
  enable_ssh_wrappers();
else disable_ssh_wrappers();

if (!get_kb_item("Host/local_checks_enabled")) exit(0, "Local checks are not enabled.");

os = get_kb_item("Host/MacOSX/Version");
if (!os) exit(0, "The host does not appear to be running Mac OS X.");

cmd = "echo ; /usr/bin/dscl . -readall /Groups GroupMembership";

res = exec_cmd(cmd:cmd);

info = '';
info2 = '';

count = 0;
if (!isnull(res))
{
  blocks= split(res, sep:'-\n', keep:FALSE);
 
  pattern = '^(GroupMembership: (.*) )?RecordName: (.*)';
  foreach block (blocks)
  {
    block = str_replace(find:'\n', replace:' ', string:block);

    if ('RecordName: admin' >< block)
    {
      matches = eregmatch(string:block, pattern:pattern);
      if (!isnull(matches))
      {
        if (matches[2] != 'unknown')
        {
          foreach user (split(matches[2], sep:' ', keep:FALSE))
          {
            count += 1;
            set_kb_item(name:"SSH/LocalAdmins/Members/"+count, value:user);
            user = data_protection::sanitize_user_enum(users:user);
            info += '  - ' + user + '\n';
          }
        }
      }
    }
    if ('RecordName: wheel' >< block)
    {
      matches = eregmatch(string:block, pattern:pattern);
      if (!isnull(matches))
      {
        if (matches[2] != 'unknown')
        {
          foreach user (split(matches[2], sep:' ', keep:FALSE))
          {
            count += 1;
            set_kb_item(name:"SSH/LocalAdmins/Members/"+count, value:user);
            user = data_protection::sanitize_user_enum(users:user);
            info2 += '  - ' + user + '\n';
          }
        }
      }
    }
  }
}

if (info || info2)
{
  if (info)
  {
    if (max_index(split(info)) == 1)
      report = '\nThe following user is a member';
    else
      report = '\nThe following users are members';

    report =
      report + ' of the \'Admin\' group :\n' +
      chomp(info) + '\n';
  }

  if (info2)
  {
    if (max_index(split(info2)) == 1)
      report += 
        '\nThe following user is a member';
    else
      report += 
        '\nThe following users are members';

    report =
      report + ' of the \'Wheel\' group :\n' +
      chomp(info2) + '\n';
  }
      
  security_note(port:0, extra:report);
}
else exit(0, 'No members of the \'Admin\' or \'Wheel\' groups were found on the remote host.');
