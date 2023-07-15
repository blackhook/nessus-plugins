#TRUSTED 323f14e536de78e677139b4235cc0086c68ceac1121d3b70072086a3c09156bf3d6e573a3b54311ba7ff8c107392ab1cbcc877c97facce2a6a0f859d7d45a3d0d3669386214a720e117c9aa87216855f15c11d13403f5c0d16ba854583f2b8a02ca068948e0559f9e1ab340dd2b35ac074f6157a3f1e3610aead82ab315d8ad4846537af82e305c0d6bd9d21c98b662713f4c60cd8b29e62a6aae161c51be09f6b63a7f27cd5c55dc4b0df9867910a8a1957a435361e8cf2f913cce14d346a178da0c3b3d0c4f927ed900b9185e5abc4f2537f42bed040ebf4adcf511e34f4d62b118e594596d3ff83abb7ba89e7261f8ea2a95bb7795d62a1e963fee84a335d13f0a90cc715156d3389cdfe0b65b9b8920fc0911f38d3a128876b3df7de54f7927fc4c5a05dddf7301e9aee126290865e5941e686e95795d4dc668b5bf03a6ae27a47c30619ebe66b54681e0051c79151f0f5be48b85ea5ec0fa0be86adce2d74f1402f26e79c9fb9fed64f1ba50ba7b8592843cd9f46bfa9f74cde3eb948803325a66046c25aa2eceafbeb7736396b4e6409354728f64f9e3dddc45228f3a4c0b764c5f5756416226bf697f40359a11563cfc3e908fb89a3124a251f3bd7ef333c026f6924047e094a65a9bc6a47974c7bae6c3554d8051b6d8cc8804b9e553418307c8f87cd6f6419f08f260440a4d63f641af66d395a6cbd3f0da1998c81
#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include("compat.inc");

if (description)
{
  script_id(157358);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/09/08");

  script_name(english:"Linux Mounted Devices");
  script_summary(english:"Generates a report detailing mounted devices on the target machine at the time of scan.");

  script_set_attribute(attribute:"synopsis", value:
  "Use system commands to obtain the list of mounted devices on the target machine at scan time.");
  script_set_attribute(attribute:"description", value:
  "Report the mounted devices information on the target machine at scan time using the following commands.
/bin/df -h
/bin/lsblk
/bin/mount -l

This plugin only reports on the tools available on the system and omits any tool
that did not return information when the command was ran.");

  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_attribute(attribute:"risk_factor", value:"None");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/02/03");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"General");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/uname");

  exit(0);
}

include("audit.inc");
include("ssh_func.inc");
include("telnet_func.inc");
include("hostlevel_funcs.inc");
include("global_settings.inc");
include("misc_func.inc");
include("data_protection.inc");

get_kb_item_or_exit("Host/local_checks_enabled");
get_kb_item_or_exit("Host/uname");

if(sshlib::get_support_level() >= sshlib::SSH_LIB_SUPPORTS_COMMANDS ||
    get_one_kb_item('HostLevelChecks/proto') == 'local') enable_ssh_wrappers();
else disable_ssh_wrappers();

# We currently only support running this against linux
# To expand support we would want to confirm we have mapping of commands correct
uname_kb = get_kb_item_or_exit("Host/uname");
if ("Linux" >!< uname_kb)
{
  audit(AUDIT_OS_NOT, "Linux");
}

if (islocalhost())
{
  if (!defined_func("pread")) audit(AUDIT_FN_UNDEF,"pread");
  info_t = INFO_LOCAL;
}
else
{
  var sock_g = ssh_open_connection();
  if (!sock_g) audit(AUDIT_FN_FAIL, 'ssh_open_connection');
  info_t = INFO_SSH;
}

var cmd = "/bin/df -h 2>/dev/null";
var df_report = info_send_cmd(cmd:cmd, timeout:300);
cmd = "/bin/lsblk 2>/dev/null";
var lsblk_report = info_send_cmd(cmd:cmd, timeout:300);
cmd = "/bin/mount -l 2>/dev/null";
var mount_report = info_send_cmd(cmd:cmd, timeout:300);

# Close ssh connection if not local
if (info_t == INFO_SSH) ssh_close_connection();

report = "";
if (!empty_or_null(df_report))
  report += '$ df -h\n' + df_report + '\n\n';
if (!empty_or_null(lsblk_report))
  report += '$ lsblk\n' + lsblk_report + '\n\n';
if (!empty_or_null(mount_report))
  report += '$ mount -l\n' + mount_report + '\n\n';
  
if (empty_or_null(report)) exit(0, "Unable to obtain drive information, commands possibly missing from system.");

security_report_v4(severity:SECURITY_NOTE, port:0, extra:report);
