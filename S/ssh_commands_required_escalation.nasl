#TRUSTED 7e7605cc03e06f5c78e536804ce9b0396799d16c5204569ed0bbd3aea54750a89de6e913cdb32fadd335ab468ddee3a53b5b4ea3fc3d7ca5f4b49ad9258773a8b319120fddc977de85da651d529e30a14724710afcfd93135e318af4dfc7260be5bf6169c3cbee331a6af85d72b08958a4c2b33433adcf36da1231b193be3cecd96c69a62ed9881af930b93a3f881ed49188a8172e52d008bac56994353ad39e4b7d6dd19f3e305f5998474eb6fcc352cddbf20f4c5bd538945865b13ee17aed560bcb1c8acead104a8a787b2fa435b769838c559a39aded14011854cc4262293d63f3f3fb3a6c32fc644ee262bb82763eafcf9bb11680d9295004941f06d713d5308543457db79bd56cd03bbf6ece86cf5fd338ad51fda96efdd3f4ad5f1e273531c400c7a2f50be22dcaab296a40e0a8353ad70aa80644e251a08165923d2bdeb5471f49a7254d2218dfde20b2d6f708e9ee692b388bb79f48c9d706b30e1d6dd12bc25e266e8830d5c007dcd5179f1c2219abf0e3b55a3a6018c9089f6bd981e9362ef9b447ff48e523b2fb9df9ce6346587a21a6ff082e8b06765fb3a1a32ab80d2fc445017b0944bc0d3dca9243264f56601107d2127b4e0ccddfb88f801957a0ded4c9338e773cf43cf386ad30625ba4235f58e7d47ea670737e4d62ceb5edbcbf6bb3068b48963bbb98142197e206f9b4505ac66b58aad3c3c63c87f3

include("compat.inc");

if (description)
{
  script_id(102095);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2018/10/02");

  script_name(english:"SSH Commands Ran With Privilege Escalation");
  script_summary(english:"Reports SSH commands that required privilege escalation to run.");

  script_set_attribute(attribute:"synopsis", value:
"This plugin reports the SSH commands that required a privilege
escalation to run successfully or were forced to use a privilege
escalation.");
  script_set_attribute(attribute:"description", value:
"The remote host required a privilege escalation in order to run one or
more SSH commands, or a privilege escalation was forced by a plugin
for one or more SSH commands.

Note that this plugin only reports if 'Attempt least privilege' is
enabled in the scan policy.");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor",value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2017/08/01");

  script_set_attribute(attribute:"plugin_type",value:"local");
  script_set_attribute(attribute:"always_run", value:TRUE);
  script_end_attributes();

  script_category(ACT_END);
  script_family(english:"Settings");

  script_copyright(english:"This script is Copyright (C) 2017-2018 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_require_keys("SSH/attempt_least_privilege");
  script_require_ports("Services/ssh", 22);

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("spad_log_func.inc");

get_service(svc:'ssh', default:22, exit_on_fail:TRUE);

get_kb_item_or_exit("SSH/attempt_least_privilege");

# Verify table exists
tables = query_scratchpad("SELECT name FROM sqlite_master WHERE type='table' AND name='ssh_cmd_log';");
if(tables[0]['name'] != "ssh_cmd_log")
  exit(0, "No SSH commands have been run using the sshlib SSH library.");

# Check for commands that used privilege escalation
used_res = query_scratchpad("SELECT user,escl_user,escl_method FROM ssh_cmd_log WHERE ran_with_priv_escl=1 AND priv_escl_failed=0");

if( (!used_res || len(used_res) == 0))
  exit(0, "No SSH commands have been logged as using privilege escalation.");

port = 0;
report =
  '\nLogin account      : ' + used_res[0]['user'] +
  '\nEscalation account : ' + used_res[0]['escl_user'] +
  '\nEscalation method  : ' + used_res[0]['escl_method'];
note = '';
target = get_host_name();
if(!target) target = get_host_ip();

# Commands that required privilege escalation
required_res = query_scratchpad("SELECT plugin, cmd, md5, user, escl_user, escl_method FROM ssh_cmd_log WHERE ran_with_priv_escl=1 AND forced_escl=0 AND priv_escl_failed=0 ORDER BY plugin ASC");

# Look up plugin IDs
db = 0;
if(nasl_level() >= 6000)
{
  if (platform() == 'WINDOWS')
    path = nessus_get_dir(N_STATE_DIR) + "\plugins-attributes.db";
  else
    path = nessus_get_dir(N_STATE_DIR) + '/plugins-attributes.db';

  db = db_open2(path:path, use_default_key:TRUE, readonly:TRUE);
  if (db <= 0)
    spad_log(message:"Failed to open database to look up plugin IDs.");
}

if(required_res && len(required_res) > 0)
{
  if(len(required_res) > 1) s = "s";
  else s = "";

  report +=
    '\nCommand'+s+' required privilege escalation :' +
    '\n  Plugins :';

  # Add a header for each plugin
  plugin = NULL;
  foreach item (required_res)
  {
    if (item['plugin'] != plugin)
    {
      plugin = item['plugin'];
      report += '\n  - Plugin Filename : ' + plugin;
      if (db > 0)
      {
        rows = db_query(db:db, query:'SELECT * FROM Plugins WHERE plugin_fname = ?', plugin);
        plugin_data = rows[0];
        if(!isnull(plugin_data))
        {
          report += '\n    Plugin ID       : ' + plugin_data.id;
          report += '\n    Plugin Name     : ' + plugin_data.plugin_name;
        }
      }
    }
    report += '\n    - Command : ' + serialize(item['cmd']);
    if('2>/dev/null' >< item['cmd'])
      note += '\n  - Command : ' + serialize(item['cmd']);
  }
  i++;
}

# 'Privilege escalation forced' is here defined as use of privilege
# escalation due to the calling plugin forcing privilege escalation
forced_res = query_scratchpad("SELECT plugin, cmd, md5, user, escl_user, escl_method FROM ssh_cmd_log WHERE ran_with_priv_escl=1 AND forced_escl=1 AND priv_escl_failed=0 ORDER BY plugin ASC");

if(forced_res && len(forced_res) > 0)
{
  if(len(forced_res) > 1) s = "s";
  else s = "";

  report +=
    '\nCommand'+s+' forced to use privilege escalation :' +
    '\n  Plugins :';

  # Add a header for each plugin
  plugin = NULL;
  foreach item (forced_res)
  {
    if (item['plugin'] != plugin)
    {
      plugin = item['plugin'];
      report += '\n  - Plugin Filename : ' + plugin;
      if (db > 0)
      {
        rows = db_query(db:db, query:'SELECT * FROM Plugins WHERE plugin_fname = ?', plugin);
        plugin_data = rows[0];
        if(!isnull(plugin_data))
        {
          report += '\n    Plugin ID       : ' + plugin_data.id;
          report += '\n    Plugin Name     : ' + plugin_data.plugin_name;
        }
      }

    }
    report += '\n    - Command : ' + serialize(item['cmd']);
    if('2>/dev/null' >< item['cmd'])
      note += '\n  - Command : ' + serialize(item['cmd']);
  }
}

if (db > 0) db_close(db);

if(!empty(note))
  report +=
    '\nCommands redirected errors, may have silently failed : ' + note;

security_report_v4(port:port, extra:report, severity:SECURITY_NOTE);
