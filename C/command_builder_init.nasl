#TRUSTED 0fa15eb51621c1d1b42b5224025f3ef8b3bad9f7bbb5fa544fcdc80c617846c62fcdf217baeb432e441e9b7f418c97dd7d85dcd8aa20991348f0e093796a6067cc19232c9998a1a3137e33d408189212ba2b2930cf38508870e02f7cf623525cefca89b1c8bb090da9632ed10562c268e8f0e89be8271ddb297fc463c7b9ecef952511fd5c476fa860c49c199181bf49e7fd5f1305170c6b7a0915a8be3a46381afa299347670b64327fe48e1a3e74c66d50a4eea27efb95f40e224e9900e65ce74af1bdb7de1aca27d5de3c9ffbaffaa0c531b4c7073b13bc4735305c800c34abff20d5fce4ea9e03371241876a993d633dcd5e3051fb7ffe8eb9f0296a275bc9a33df5229d9ef43776966eb09e4cc54aeaefa9393ea5705cb9acdbc69405a2b6306fa5eecc013a0fc4808ca5775c255fb6e3dd3bcb5f161bd2f8ed5bacf1c8315c3a85545c838b751e6ae17254e1082963022efebc02b4bcbffd5209fc1cf4fce6635a6fc095ea377681f246138f28e7e496995813300cfb9782468b122d4ded3e30903486b6e506d7a863b8d75f22c58e1ab9f18adfca87d707be00e21e087be1984f40e513b5d6e320d02242fbb897d95f7859edb9e14c38fb363ad3f85e0b3c3edd69d3eb8d671c953e5057646a01c3004ccb32d2840565bf42645030059280ce20dc6d06f631c4f6492a946e37f792e682b87fff0a07ea31887624eda5

#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(131286);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/06/29");

  script_name(english:"Command Builder Initialization");
  script_summary(english:"Initialize command builder library.");

  script_set_attribute(attribute:"synopsis", value:
"Query host to initialize command builder functionality.");
  script_set_attribute(attribute:"description", value:
"Query host for the existance and functionality of commands wrapped by the command builder library.");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2019/11/25");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"agent", value:"unix");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"General");

  script_copyright(english:"This script is Copyright (C) 2019-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled");

  exit(0);
}

include("global_settings.inc");
include("audit.inc");
include("ssh_func.inc");
include("telnet_func.inc");
include("hostlevel_funcs.inc");
include("misc_func.inc");
include("command_builder.inc");
include("sh_commands_find.inc");
include("spad_log_func.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

uname = get_kb_item("Host/uname");

if (isnull(uname)) uname = '';

if ("Linux" >< uname ||
    "Darwin" >< uname ||
    get_kb_item("Host/Solaris/Version") ||
    get_kb_item("Host/Solaris11/Version") ||
    get_kb_item("Host/AIX/version") ||
    get_kb_item("Host/HP-UX/version") ||
    get_kb_item("Host/FreeBSD/release") )
{
  if(sshlib::get_support_level() >= sshlib::SSH_LIB_SUPPORTS_COMMANDS ||
    get_one_kb_item('HostLevelChecks/proto') == 'local')
  {
    enable_ssh_wrappers();
  }
  else
  {
    disable_ssh_wrappers();
  }

  if (islocalhost())
  {
    if (!defined_func("pread") )
    {
      spad_log_and_exit(exit_level:1, exit_msg:"'pread()' is not defined.");
    }
    info_t = INFO_LOCAL;
  }
  else
  {
    sock_g = ssh_open_connection();
    if (!sock_g)
    {
      spad_log_and_exit(exit_level:1, exit_msg:"Failed to open an SSH connection.");
    }

    info_t = INFO_SSH;
  }

  command_builder::init_cmd_runner();
  sh_commands_find::init_find();

  if(info_t == INFO_SSH) ssh_close_connection();

  exit(0);
}
else
{
  exit(0, "Unsupported operating system.");
}


