#TRUSTED 88145761b7a3e18833e8e3a90b903c87b4f7995143129e47d8be46fda8dc669357007e283ceab8777ed571ccaab7090cf8a70b3abccf8ca1fdaf8a30bbdaad272bf2fc92732fa8048b51f53223c13904be691b5cd70ea777fe35876c33e5bdc3cea41f210588c723875c082b3b7e5a3c1db28a292113a645bb2fa2ad388b622706827dc30728c45e2231c0f263013a3a3094a027d3e4e97006d1bcf015819918c34f63e2c736d950256f65d8f7ae8d3a25c46a5a10643c54743f59eb610c1ac27f6b015759e5087f2f65011cccd86f34621bb794b100ebc56229a4844274e05836e21fdb5a01ef481cd8b177c36dc3923dffdda1dedd3c463aa2213bd883f34552ce13e16e3feffecdbccc3b032e73d6a5b6c90f75bbbf877c6fc6095dad83b336116dc45df50f1d6f1d3713d0a67869cd5658a57c30a4b681a2f9f1aa04b3bf2fb5e20d7e80eaf046020e4585b1ca185559fe6e7fe0de3a28390b3ebb281295da6bb662d477ff3486b4214f351699b47664cdb6e289d5d81ae9cf65bf077fec8249aa42b441af2240bfa1cb2d7c16c08990f2c9b181d5c77d22985c82fdc36bae08d318a8608aa57270b11c12cf014f31b27b4eddb7ae19cbe56eb42a2eec1ce3da6a04f3632a8a7dce37b2b1519b773be5617f0b57e03f88fa560310ccbcd13ea79405df5d2c046fe8a119021d40af4c077163be323a74ba669d4873488990
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(56299);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/06/29");

  script_name(english:"Linux /proc/cpuinfo");
  script_summary(english:"Read /proc/cpuinfo");

  script_set_attribute(attribute:"synopsis", value:
"The processor's type and features can be read.");
  script_set_attribute(attribute:"description", value:
"/proc/cpuinfo could be read.  This file provides information on the
processor's type and features on Linux systems.");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/09/26");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2011-2022 Tenable Network Security, Inc.");
  script_family(english:"Misc.");

  script_dependencies("ssh_settings.nasl", "ssh_get_info.nasl");
  script_require_keys('HostLevelChecks/proto');
  exit(0);
}

include("misc_func.inc");
include("ssh_func.inc");
include("telnet_func.inc");
include("hostlevel_funcs.inc");


if(sshlib::get_support_level() >= sshlib::SSH_LIB_SUPPORTS_COMMANDS ||
    get_one_kb_item('HostLevelChecks/proto') == 'local')
  enable_ssh_wrappers();
else disable_ssh_wrappers();

if (!get_kb_item('HostLevelChecks/proto')) exit(0, "Local checks are not enabled for the remote host.");

uname = get_kb_item("Host/uname");
if ("Linux" >!< uname) exit(0, 'The remote host is not running Linux.');

# We may support other protocols here
if ( islocalhost() )
{
 if ( ! defined_func("pread") ) exit(1, "'pread()' is not defined.");
 info_t = INFO_LOCAL;
}
else
{
 sock_g = ssh_open_connection();
 if (! sock_g) exit(1, "ssh_open_connection() failed.");
 info_t = INFO_SSH;
}

cmd = 'LC_ALL=C cat /proc/cpuinfo';
buf = info_send_cmd(cmd: cmd);
if (info_t == INFO_SSH) ssh_close_connection();

if (egrep(string:buf, pattern:'^processor[ \t]*:'))
{
  set_kb_item(name:'Host/proc/cpuinfo', value: buf);
  m = eregmatch(string: buf, pattern:'\nmodel name[ \t]*:[ \t]*(.*[^ \t])[ \t]*\n');
  if (! isnull(m))
    set_kb_item(name:'Host/proc/cpu_model_name', value: m[1]);
  exit(0);
}
else exit(1, "/proc/cpuinfo could not be read.");
