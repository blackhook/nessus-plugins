#TRUSTED 44fd7df44510aa31c3ce107c5588df075ef598fbc9ce00430ecaf4d3d2cee66d53a62a9c70f7ea98dc1053ee0596144ae337e96d8907b337aaab278b68b0777010c6f7ddb52617121d50b4d0e702967966983e32f0559c6d07123f12949b23c26e43d16f6427c7441143badaa125824b0f3923a75726305f0d3f060f9c199f2296e5a9c3501995872b31f74d9f03de6142f92debab31950653e2fe6e9198aa2daa346b14ca52ee2c1b96289b4642ce14eee3042c3bf7f0db7a1cece3fb954c50d089b0086f0d401a2272706544069c98f391ac814d4e2df23b3d01a4a25a92d0a98b3a5e3cb66ba3211ff4a78867790ea716c32ede95925ffc526d311cdca98d1fd1f09fbc5136b62fa3690b3a4e0fa1f79011a21e67914f642436af4fbfb8374afa8ec82adf5ecdf3ada14f093a0d20b3fa12074d72f5aaebdef252356c60334f67b028b4a53ce7e5b0477280d396708b4527d7e5730010a7d9b98bc44c619ac0d68b883de72ce674af66c555149b76cca343a9e7fa5d4aa1839b6884c7f3e462db4e76eabe42316fcc5ec6da72283c41f03d5d7f0ac357369081a2b4a94c5ac7e0e753a0e110320af5f6fcdb165c4d729ffa249428e389c1743e465307d0b21f1591dffe298c0fa50cfbf8ca3f66cb8d4d75fc6518f22d928c01c58f958f732bfc2bf63dc4045883ea710dd09bb43d42137d90a023b12b79bcc6871b80da8d
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(69130);
  script_version("1.18");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/10/12");

  script_name(english:"Cisco Wireless Control System Installed (Linux)");
  script_summary(english:"Looks for WCS files");

  script_set_attribute(attribute:"synopsis", value:
"A wireless management application is installed on the remote Linux
host.");
  script_set_attribute(attribute:"description", value:
"Cisco Wireless Control System (WCS) is installed on the remote host.
WCS is used as the management component for Cisco Unified Wireless
Network.");
  # https://www.cisco.com/c/en/us/products/wireless/wireless-control-system/index.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?068db457");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");
  script_set_attribute(attribute:"agent", value:"unix");

  script_set_attribute(attribute:"plugin_publication_date", value:"2013/07/30");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:wireless_control_system_software");
  script_set_attribute(attribute:"asset_inventory", value:"True");
  script_set_attribute(attribute:"asset_inventory_category", value:"software_enumeration");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2013-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("HostLevelChecks/proto", "Host/uname");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("ssh_func.inc");
include("telnet_func.inc");
include("hostlevel_funcs.inc");
include("install_func.inc");

app = 'Cisco WCS';

if(sshlib::get_support_level() >= sshlib::SSH_LIB_SUPPORTS_COMMANDS ||
    get_one_kb_item('HostLevelChecks/proto') == 'local')
  enable_ssh_wrappers();
else disable_ssh_wrappers();

if ("Linux" >!< get_kb_item_or_exit("Host/uname"))
  audit(AUDIT_OS_NOT, "Linux");

proto = get_kb_item_or_exit('HostLevelChecks/proto');

if (proto == 'local')
  info_t = INFO_LOCAL;
else if (proto == 'ssh')
{
  info_t = INFO_SSH;
  ret = ssh_open_connection();
  if (!ret)
  {
    error = get_ssh_error();
    if (error)
      extra = ' (' + error + ')';
    else
      extra = '';
    exit(1, 'ssh_open_connection() failed' + extra + '.');
    audit(AUDIT_FN_FAIL, 'ssh_open_connection');
  }
}
else
  exit(0, 'This plugin only attempts to run commands locally or via SSH, and neither is available against the remote host.');

nmsadmin = info_send_cmd(cmd:'grep ^NMSADMIN= /etc/init.d/WCS*');
install_count = 0;

foreach line (split(nmsadmin, sep:'\n', keep:FALSE))
{
  # examples:
  # NMSADMIN=/opt/WCS6.0.132.0/bin/nmsadmin.sh
  # NMSADMIN=/usr/local/wcs/bin/nmsadmin.sh
  match = pregmatch(string:line, pattern:"NMSADMIN=(.+)/bin/nmsadmin\.sh");
  if (isnull(match)) continue;

  # only assume that the install is valid if the plugin is able to get
  # its version number from a file under the installation root
  path = match[1];
  prop_file = path + '/webnms/classes/com/cisco/common/ha/config/ha.properties';
  prop_file = str_replace(string:prop_file, find:"'", replace:'\'"\'"\'');  # replace ' with '"'"' to prevent command injection
  cmd = 'grep ^version= ' + prop_file;
  ver_prop = info_send_cmd(cmd:cmd);

  # example:
  # version=6.0.132.0
  match = pregmatch(string:ver_prop, pattern:'^version=([0-9.]+)$');
  if (isnull(match)) continue;

  version = match[1];
  set_kb_item(name:'cisco_wcs/version', value:version);
  set_kb_item(name:'cisco_wcs/' + version + '/path', value:path);
  register_install(
    app_name:app,
    vendor : 'Cisco',
    product : 'Wireless Control System Software',
    path:path,
    version:version,
    cpe:"cpe:/a:cisco:wireless_control_system_software");

  install_count += 1;
}

if(info_t == INFO_SSH) ssh_close_connection();

if (!install_count)
  audit(AUDIT_NOT_INST, app);

report_installs(app_name:app);

