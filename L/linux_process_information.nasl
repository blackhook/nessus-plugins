#TRUSTED 3e8631aa4e5f95b94092efca9af71d8d0072b110702020a0d012fae076d17fe71f5727136038c1504ff6b17f957762004ac4d15a4f05c2ebd73be8e2264d7f6977d2af68d508d07078d27677fe31e05b7ced81171944cc8f28e86bf1c9ffba2b21cd7e8e157e48bbba887088004f195c712402f0968c9db93a49f93f612e9406492747e369b5149871e31be90771d23a20249996297f504e84ed12072ccf639aff893aee75fc89d7048f5959c9d0f433f38652024ea4bd726025b27393d93fad8a5ae4689be359e58ac4c2ea1f83ce57069db46ed62b04af9f8aef1da64207b76b4dff568debc2a2de04b0caffda92dbc1b908f3768640aa26afdae25e7ebd38556cfa158a9cce34a9f4cabb755cef46ed454996643019f6760dbe37d1503bdac04ff2952a09736134852e7307d7ba929cf2a621d026c93d713c2c5e0c0b629a55756517c818b5a449a282f32b3fc12893a3ce51120f8c621c921c3f448ed44d8db9b4acbdbbac6d82ccfcfc2755584490b22d4ac09dac1f434cfc3099c3a191f414b1b4a74aa73cb4cd30010c130c8e83e3ad8fecd900ee8d922140918ad6fda6f035bbb2141568e22d6dc3abc43716d06e1c252e0b58a38601061801a0495bf57a6f700e3cff1d9cc644b2157fe5b8f24f7533d9d7f8b69e32e0abaa202f68886cfa11e905f38de2dc9b67894eff4791a7dc2e39bb26c0e6ddb2d490c7eac0
#
# (C) Tenable Network Security, Inc.
#

if (!defined_func("nasl_level") || nasl_level() < 5200) exit(0, "Not Nessus 5.2+");

include("compat.inc");

if (description)
{
  script_id(110483);
  script_version("1.17");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/06/29");

  script_name(english:"Unix / Linux Running Processes Information");
  script_summary(english:"Generates a report detailing running processes on the target machine at the time of scan.");

  script_set_attribute(attribute:"synopsis", value:
  "Uses /bin/ps auxww command to obtain the list of running processes on the target machine at scan time.");
  script_set_attribute(attribute:"description", value:
  "Generated report details the running processes on the target machine at scan time.
  This plugin is informative only and could be used for forensic
  investigation, malware detection, and to confirm that your system
  processes conform to your system policies.");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_attribute(attribute:"risk_factor", value:"None");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/06/12");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"General");

  script_copyright(english:"This script is Copyright (C) 2018-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/uname", "Host/hostname");

  exit(0);
}

include("audit.inc");
include("ssh_func.inc");
include("telnet_func.inc");
include("hostlevel_funcs.inc");
include("global_settings.inc");
include("misc_func.inc");
include("data_protection.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/uname")) audit(AUDIT_KB_MISSING, "Host/uname"); 
if (!get_kb_item("Host/hostname")) audit(AUDIT_KB_MISSING, "Host/hostname");

if(sshlib::get_support_level() >= sshlib::SSH_LIB_SUPPORTS_COMMANDS ||
    get_one_kb_item('HostLevelChecks/proto') == 'local')
  enable_ssh_wrappers();
else disable_ssh_wrappers();

# Support both Linux and Mac
uname_kb = get_kb_item_or_exit("Host/uname");
if (
    "Linux" >!< uname_kb && 
    "FreeBSD" >!< uname_kb && 
    "Darwin Kernel Version" >!< uname_kb && 
    "AIX" >!< uname_kb &&
    "SunOS" >!< uname_kb
   )
  audit(AUDIT_OS_NOT, "Linux");

if (islocalhost())
{
  if (!defined_func("pread")) audit(AUDIT_FN_UNDEF,"pread");
  info_t = INFO_LOCAL;
}
else
{
  sock_g = ssh_open_connection();
  if (!sock_g) audit(AUDIT_FN_FAIL, 'ssh_open_connection');
  info_t = INFO_SSH;
}

# Should work on all *nix environments, but doesn't on Solaris 10
os = get_kb_item("Host/OS");
if (os =~ "solaris 10")
  cmd = "/bin/ps -ef 2>/dev/null";
else
  cmd = "/bin/ps auxww 2>/dev/null";

report = info_send_cmd(cmd:cmd, timeout:300);
if (info_t == INFO_SSH) ssh_close_connection();

if (os =~ "solaris 10")
{
  if (empty_or_null(report) || "CMD" >!< report)
    exit(1, "Failed to extract the list of running processes.");
}
else if ((empty_or_null(report)) || ("COMMAND" >!< report))
{
  exit(1, "Failed to extract the list of running processes.");
}

# usernames can be in the path /etc, safest not to display anything
if (data_protection::is_sanitize_username_enabled())
{
  report = 'Process Information is not available because data protection services are enabled.';
}

replace_kb_item(name:"Host/ps_auxww", value:report);
security_report_v4(severity:SECURITY_NOTE, port:0, extra:report);
