#TRUSTED 2f295a7ddc3e9314a74e49143fbb37bbcfb2e185698929e8955d7eed46d5c3f7de0deb533aa07271cedc105c1d7518a397ae0139a2bb5972578d38af54841b299692194cf13e446c52775999dbbc951b761c00d3d765cf2d3cd8aefe5ba352610877cfd666d6764766c8cc3d9beaf18ce6d0ec9a963f6b57b4c3a1c8709d8cb3b6d812e682e5502f265e089466d2a1b7e8127b2815f853e54504054c949c2d25e8b5cf5b73bcb0e7ebed7b3c02bb545c560ea1be011ae69b67cfab2786ca4494950e0ed122ce35627f073c41a4cdbc2d44b29990fe372817d81b51a3ac7575d6378151fdb8308f622c5ce6ba17266daf436857e5f450a7da05eab6cd80e711e626613cd4e862b7c5ec3e6a06f189e66672ef091198c7c1a7a8b9d20e0d9f925ac753fa30e58ce91030d76f322e49f63e21d01d48c53c64200e245e626bfb75f6edd2f848a68da5f025f65f6edf257fa0e1fdad51304026be89643e711d7642347b30b5bc86b7898984a5bfd15898664f84179394f363bab76eac7a4c75812ba5938e48d7c8e47e68782e192e1f845e2fb396db01a4f73b91863431adc2c9e5f6544d2cdc7461b75736c519a9b235dba52ec4a972b47993a1e58eda53b843d7b99d9e425d1b6b7fe1e26052a3af4dac3809bdcd8097b3bd1085da10391b7a697df5c96fd384c77289f1d4e067b2ed9a22b3cbcdb603db39e36b329a18711560ec

include("compat.inc");

if (description)
{
  script_id(102094);
  script_version("1.13");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/09/22");

  script_xref(name:"IAVB", value:"0001-B-0507");

  script_name(english:"SSH Commands Require Privilege Escalation");
  script_summary(english:"Reports SSH commands that require privilege escalation.");

  script_set_attribute(attribute:"synopsis", value:
"This plugin reports the SSH commands that failed with a response
indicating that privilege escalation is required to run them.");
  script_set_attribute(attribute:"description", value:
"This plugin reports the SSH commands that failed with a response
indicating that privilege escalation is required to run them. Either
privilege escalation credentials were not provided, or the command
failed to run with the provided privilege escalation credentials. 

NOTE: Due to limitations inherent to the majority of SSH servers, 
this plugin may falsely report failures for commands containing 
error output expected by sudo, such as 'incorrect password', 
'not in the sudoers file', or 'not allowed to execute'.");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor",value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2017/08/01");

  script_set_attribute(attribute:"plugin_type",value:"local");
  script_set_attribute(attribute:"always_run", value:TRUE);
  script_end_attributes();

  script_category(ACT_END);
  script_family(english:"Settings");

  script_copyright(english: "This script is Copyright (C) 2017-2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_require_ports("Services/ssh", 22);

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("spad_log_func.inc");

get_service(svc:'ssh', default:22, exit_on_fail:TRUE);

# Verify table exists
tables = query_scratchpad("SELECT name FROM sqlite_master WHERE type='table' AND name='ssh_cmd_log';");

if(tables[0]['name'] != "ssh_cmd_log")
  exit(0, "No SSH commands have been run using the sshlib SSH library.");

# Check for commands that failed privilege escalation or appear to
# need privilege escalation that was not provided
res = query_scratchpad("SELECT user FROM ssh_cmd_log WHERE failed_needs_escl=1 OR priv_escl_failed=1");

if(!res || len(res) == 0)
  exit(0, "No SSH commands have been logged as failed due to requiring additional privileges.");

port = 0;
report = '\nLogin account : ' + res[0]['user'];
target = get_host_name();
if(!target) target = get_host_ip();

# 'Privilege escalation needed' means that the command response indicated
# that the command failed without escalation and we were not able to try
# escalation
needs_escl_res = query_scratchpad("SELECT user,escl_user,escl_method,plugin,cmd,md5,error,response FROM ssh_cmd_log WHERE failed_needs_escl=1 ORDER BY escl_user,plugin ASC");

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

if(needs_escl_res && len(needs_escl_res) > 0)
{
  if(len(needs_escl_res) > 1) s = "s";
  else s = "";

  report +=
    '\nCommand'+s+' failed due to lack of privilege escalation :';

  # Add a header for each user and each plugin
  escl_user   = -1;
  escl_method = -1;
  foreach item (needs_escl_res)
  {
    if (item['escl_user'] != escl_user)
    {
      escl_user = item['escl_user'];
      if(empty_or_null(escl_user)) display_escl_user = "(none)";
      else display_escl_user = escl_user;
      escl_method = item['escl_method'];
      if(empty_or_null(escl_method)) display_escl_method = "(none)";
      else display_escl_method = escl_method;
      plugin = item['plugin'];
      report +=
        '\n- Escalation account : ' + display_escl_user +
        '\n  Escalation method  : ' + display_escl_method +
        '\n  Plugins :' +
        '\n  - Plugin Filename : ' + plugin;
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
    else if (item['plugin'] != plugin)
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
    report +=
      '\n    - Command  : ' + serialize(item['cmd']) +
      '\n      Response : ' + serialize(item['response']) +
      '\n      Error    : ' + serialize(item['error']);
  }
  i++;
}

# 'Privilege escalation failed' means that we tried to escalate privileges
# but the command response indicated a failure
failed_escl_res = query_scratchpad("SELECT user,escl_user,escl_method,plugin, cmd, md5,error,response FROM ssh_cmd_log WHERE priv_escl_failed=1 ORDER BY plugin ASC");

if(failed_escl_res && len(failed_escl_res) > 0)
{
  if(len(failed_escl_res) > 1) s = "s were";
  else s = " was";

  report +=
    '\nCommands failed due to privilege escalation failure:';

  # Add a header for each user and each plugin
  escl_user = -1;
  escl_method = -1;
  foreach item (failed_escl_res)
  {
    if (item['escl_user'] != escl_user)
    {
      escl_user = item['escl_user'];
      if(empty_or_null(escl_user)) display_escl_user = "(none)";
      else display_escl_user = escl_user;
      escl_method = item['escl_method'];
      if(empty_or_null(escl_method)) display_escl_method = "(none)";
      else display_escl_method = escl_method;
      plugin = item['plugin'];
      report +=
        '\n- Escalation account : ' + display_escl_user +
        '\n  Escalation method  : ' + display_escl_method +
        '\n  Plugins :' +
        '\n  - Plugin Filename : ' + plugin;
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
    else if (item['plugin'] != plugin)
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
    report +=
      '\n    - Command  : ' + serialize(item['cmd']) +
      '\n      Response : ' + serialize(item['response']) +
      '\n      Error    : ' + serialize(item['error']);
  }
}

if (db > 0) db_close(db);

security_report_v4(port:port, extra:report, severity:SECURITY_NOTE);
