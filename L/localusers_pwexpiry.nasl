#TRUSTED 51daeea0990d19ec0760baab4322a5e32e5c1c67c08977700deba76f81ce1740f523566d65de4e71eefa7d393045d27527093a4374d7846083a76227457a18100fd0603954bd162047c8420e875029844843bf259d01246894478b39d7b98573861ad7047890078e48b1282d7aece96ce8244f8f00c661f63d1cd42748dde406ac87ce6765be901cc631f69d1f78dbb9de1d67840ebae0c9a38d4610fcece9c5c6aafa58c9cef609d7afbf515f52fb0eb2a3929a0e59eafd3c4d7a7237779fcdcb7bebcc74ce240d0fb5be5cddd8bf49c6105d563578dd052bdf9436e37d66df894fb0e436b512ffee3ab002b8cc7c7bec7a78acdb1810283f4ee26916d0946ce7628985d974f756ec69f3f9cf46a9c9368f86cf4dbbf848e9d290cef50e85a6026ec7e928bc62dc7c79f7ceb9d2887bc9fafaf9a6d4a14d8e6fe1023409f789b3ce933806c8afd88d3dd18309ceff83799a7d13f2c8f53b1092eaf6216f9cdb60731e827aea586f3e6d6d799a14c183a63c384a6045627d4b732f6893f59332d2d062e39c38052affa7da30f6aa67878354c8b1e4629c3792f26cf7a4b9f8625998126dba376dfcb7d0644109785523f678f8860ad9ec44b8cb766a2612ca3797429b5f2f69fc6390820ddf5a4c861d658607002c6c2b36ab6bffcb589893fc6564962a1fd22910c735a65208c5d79fbe3946b8b730dffb9ab5f6d24532af9b
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(83303);
  script_version("1.13");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/06/29");


  script_name(english:"Unix / Linux - Local Users Information : Passwords Never Expire");
  script_summary(english:"Lists local users whose passwords never expire.");

  script_set_attribute(attribute:"agent", value:"unix");
  script_set_attribute(attribute:"synopsis", value:
"At least one local user has a password that never expires.");
  script_set_attribute(attribute:"description", value:
"Using the supplied credentials, Nessus was able to list local users
that are enabled and whose passwords never expire.");
  script_set_attribute(attribute:"solution", value:
"Allow or require users to change their passwords regularly.");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2015/05/10");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2015-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled");

  exit(0);
}

include("audit.inc");
include("ssh_func.inc");
include("telnet_func.inc");
include("hostlevel_funcs.inc");
include("global_settings.inc");
include("misc_func.inc");
include("data_protection.inc");

if(sshlib::get_support_level() >= sshlib::SSH_LIB_SUPPORTS_COMMANDS ||
    get_one_kb_item('HostLevelChecks/proto') == 'local')
  enable_ssh_wrappers();
else disable_ssh_wrappers();

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

# Do not run against Windows and some Unix-like systems
supported = FALSE;
dist = "";
if (
  get_kb_item("Host/CentOS/release") ||
  get_kb_item("Host/Debian/release") ||
  get_kb_item("Host/Gentoo/release") ||
  get_kb_item("Host/Mandrake/release") ||
  get_kb_item("Host/RedHat/release") ||
  get_kb_item("Host/Slackware/release") ||
  get_kb_item("Host/SuSE/release") ||
  get_kb_item("Host/Ubuntu/release")
)
{
  supported = TRUE;
  dist = "linux";
  field = 5;
}
else if (
  get_kb_item("Host/FreeBSD/release") 
)
{
  supported = TRUE;
  dist = "bsd";
  field = 6;
}

if (!supported) exit(0, "Account expiration checks are not supported on the remote OS at this time.");

# We may support other protocols here
if ( islocalhost() )
{
  if (!defined_func("pread")) exit(1, "'pread()' is not defined.");
  info_t = INFO_LOCAL;
}
else
{
  sock_g = ssh_open_connection();
  if (!sock_g) audit(AUDIT_FN_FAIL, 'ssh_open_connection');
  info_t = INFO_SSH;
}

if (dist == "linux")
  cmd = "cat /etc/shadow";
else
  cmd = "cat /etc/master.passwd";

validfile = FALSE;
noexpiry = make_list();
buf = info_send_cmd(cmd:cmd);
if (info_t == INFO_SSH) ssh_close_connection();
if (buf)
{
  lines = split(buf);
  if (!empty_or_null(lines))
  {
    foreach line (lines)
    {
      acct_fields = split(line, sep:':', keep:FALSE);
      if (max_index(acct_fields) >= 7)
      {
        validfile = TRUE;
        # Skip locked / expired accounts
        if (acct_fields[1] == '*' || acct_fields[1] == '!' || acct_fields[1] == "!!" || acct_fields[1] == "!*")
          continue;
        if (dist == "bsd" && acct_fields[1] =~ '\\*LOCKED\\*')
          continue;

        if (dist == "linux" && !empty_or_null(acct_fields[7]))
        {
          if (!empty_or_null(acct_fields[6]))
            timetoexpire = int(acct_fields[6]) * 86400;
          else timetoexpire = 0;

          expire_timestamp = int(acct_fields[7]) * 86400 + timetoexpire;
          current_timestamp = unixtime();
          if (expire_timestamp < current_timestamp)
            continue;
        }

        if (empty_or_null(acct_fields[field - 1]) || int(acct_fields[field - 1]) == 99999 || (dist == "bsd" && acct_fields[field - 1] == 0))
          noexpiry = make_list(noexpiry, acct_fields[0]);
      }
    }
  }
}
else
{
  errmsg = ssh_cmd_error();
  if ('Permission denied' >< errmsg)
    exit(1, "The supplied user account does not have sufficient privileges to read the password file.");
  else
    exit(1, errmsg);
}
if (!validfile)
  exit(1, "The password file did not use the expected format.");

if (!empty_or_null(noexpiry))
{
  count = 0;
  foreach user (noexpiry)
  {
    count += 1;
    set_kb_item(name:"SSH/LocalUsers/PwNeverExpires/"+count, value:user);
  }

  if (report_verbosity > 0)
  {
    users = join(noexpiry, sep:'\n  - ');
    users = data_protection::sanitize_user_enum(users:users);
    report =
      '\nNessus found the following unlocked users with passwords that do not expire :' +
      '\n  - ' + users + '\n';
    security_note(port:0, extra:report);
  }
  else security_note(0);
  exit(0);
}
audit(AUDIT_HOST_NOT, 'affected');
