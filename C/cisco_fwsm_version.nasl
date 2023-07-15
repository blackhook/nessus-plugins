#TRUSTED 2c0419a1eece32e4c774a03914862aedd7ebc430f0858ebae19726d39058d2a6de8b93bfa3a129f0225e063edc9f0aecea097273b39eeeef668a0f24b15061dad3ac5d545b1f79ad78b07326b534722b109aafeed5d3f79d7efca82bb38a0eb1b2acda8cbbef5a46cf5b5109d3a4de55b5b31dfbbe0639419bdfe70ee3ef190816b53447bc1ada4fc66142de622dbe3e7459d189857e7aa641d5a86fc2803db815279eabd94f8ccf595ed7dca736d0d552cc6754a591037752273f61bee4d5b03ac3c0c37cca9c49e02fa212bcf409c755976f10e2e253d32f6670ba8103f498fb1c1b6cc2127707045fa8ab5f6faf86d51eb6c3ba3aaa88d4018df953e6e648c7f968693990d77ee6f365a2fe0e6b7342a42e9f0ce568b85aaaca4abb9f67aaa3871ce65a739a541ef07e70d201fb2445b5c7eb9b6f9e17a7620e6a1895e0682097ec5cce0b7d4bf03dca55bfe9d593210652a5664f362438bce5d8cfae642f2bc0c3d4002ee1a4dbf2eecbddc42f50e87d62347749515efc02df87e8a5281dc6e09389520b0035d6148e1bcb45316707eb89e3115c7c86e85e104cc530a583414b5c73c04ecde42675372ccfc4400ad1562ce2198431298137e7bbbcb3f86a518ebc232b8c1033631aa8e23de64d4728e2b2417e1d2c47a54fb4f1c8ef904dfa0345df6313fbc8b2329425917d264c0e7fa38d148e2bd388d383953dc7ce78
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(69922);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/06/29");

  script_name(english:"Cisco Firewall Services Module (FWSM) Version");
  script_summary(english:"Obtains the version of the remote FWSM");

  script_set_attribute(attribute:"synopsis", value:
"It is possible to obtain the FWSM version of the remote Cisco
device.");
  script_set_attribute(attribute:"description", value:
"The remote host has a Cisco Firewall Services Module (FWSM). 

It is possible to read the FWSM version by connecting to the switch
using SSH.");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2013/09/17");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:cisco:firewall_services_module");
  script_set_attribute(attribute:"asset_inventory", value:"True");
  script_set_attribute(attribute:"hardware_inventory", value:"True");
  script_set_attribute(attribute:"os_identification", value:"True");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);

  script_copyright(english:"This script is Copyright (C) 2013-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"CISCO");

  script_dependencies("cisco_ios_version.nasl");
  script_require_keys("Host/Cisco/IOS/Version");
  script_require_ports("Services/ssh", 22);
  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("ssh_func.inc");
include("hostlevel_funcs.inc");


if(sshlib::get_support_level() >= sshlib::SSH_LIB_SUPPORTS_COMMANDS ||
    get_one_kb_item('HostLevelChecks/proto') == 'local')
  enable_ssh_wrappers();
else disable_ssh_wrappers();

##
# Saves the provided FWSM version number in the KB, generates plugin output,
# and exits.
#
# @anonparam ver FWSM version number
# @anonparam source protocol used to obtain the version
# @return NULL if 'ver' is NULL,
#         otherwise this function exits before it returns
##
function report_and_exit(ver, source)
{
  local_var report;

  set_kb_item(name:"Host/Cisco/FWSM/Version", value:ver);

  replace_kb_item(name:"Host/Cisco/FWSM", value:TRUE);

  if (report_verbosity > 0)
  {
    report =
      '\n  Source  : ' + source +
      '\n  Version : ' + ver;
    report += '\n';
    security_note(port:0, extra:report);
  }
  else security_note(0);

  exit(0);
}

# verify that the target system is a cisco IOS
get_kb_item_or_exit("Host/Cisco/IOS/Version");

# Require local checks be enabled
if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

# Try to extract the FWSM version from the "show module" command
sock_g = ssh_open_connection();
if (!sock_g) exit(1, "Failed to open an SSH connection.");
fwsm_ssh1 = ssh_cmd(cmd:"show module", nosudo:TRUE, nosh:TRUE, cisco:TRUE);
ssh_close_connection();

if (!isnull(fwsm_ssh1) && "Firewall Module" >< fwsm_ssh1)
{
  # 4    6    Firewall Module                        WS-SVC-FWM-1      SAxxxxxxxxx
  module = eregmatch(string:fwsm_ssh1, pattern:"(\d+)\s+\d+\s*Firewall Module");

  if (!isnull(module))
  {
    # now execute the "show module #" command where # is the FWSM module number
    sock_g = ssh_open_connection();
    if (!sock_g) exit(1, "Failed to open an SSH connection.");
    fwsm_ssh2 = ssh_cmd(cmd:"show module " + module[1], nosudo:TRUE, nosh:TRUE, cisco:TRUE);
    ssh_close_connection();

    if (!isnull(fwsm_ssh2) && "Firewall Module" >< fwsm_ssh2)
    {
      # Mod MAC addresses                     Hw     Fw           Sw           Status
      # --- --------------------------------- ------ ------------ ------------ -------
      # 4   0003.e4xx.xxxx to 0003.e4xx.xxxx  3.0    7.2(1)       3.2(3)       Ok
      version = eregmatch(string:fwsm_ssh2, pattern:"[\r\n][^\r\n]+\s+([0-9][0-9\.\(\)]+)\s+Ok");

      if (!isnull(version))
      {
        report_and_exit(ver:version[1], source:'SSH');
        # never reached
      }
    }
  }
}

exit(0, 'The Cisco FWSM version is not available (the remote host may not be Cisco FWSM).');
