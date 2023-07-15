#TRUSTED a551d7392bffe28dbb10bf0ffce6c367ccd2ec21489afdfbcc949a0b8632dae41890605d06a47832ece526100ab9fd84f020619536013b5ed03b2fd67877d1cdf487b6c91ff42821df4b6e695a3e6fd8babcbea892e2763cd6e14b517092e710211330064ad83d42f7eacec0732c3164e3682b654cac6f08be66930f2da14c579607f6e979c1644d96405bbe7cba89e6e70b51afb1bf184d9d116ae2532114435c12a00b0aeb7a3d2b6ac26f4d9c79b39560ed8b8d8adfa187c9a5f3e3b62280634a00c6c74e691c59f98a428ccc90a182f86b54f110b0c93187bdde83a8ca9a42743e3203437ab353691bbb005add2b1d5cac6655e19bb0dcee1bb7564882e0bc1b2c86e627f79253197c1bb0b6a42dbee387499077c45604c1e63c4e59e419392dff480725956e503e456f9e9486ab445053043497f46adf901800ceef526a3ac2db0180782258b716fd7fd98ed4be413b50a659ff9f2803b5b11103f1690f2fb528d288d2438de239573326ad153f51d8fc03fa498cacb00e98a98bacdef1563828c314f5ddd5904add9e8e443cf793925c27674bb1786d9a2a5ea1eec4236e1099bd31dd6e39418ead2dcfbd346a46fd8b1ad6ba0b6f6462de7a950ee7f5949c8a0282606bf690540726f5424e8b3b981289b475e75a391368a5f588e41b35d6228ef043c676419b9bc691ce0fcbfe4cc8d9da6886591b8e3d8792200c28
#
# (C) Tenable Network Security, Inc.
#


if (!defined_func("bn_random")) exit(0);


include("compat.inc");


if (description)
{
  script_id(50680);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/06/29");

  script_name(english:"Mac OS X Server Service List");
  script_summary(english:"Report list of installed services");

  script_set_attribute(
    attribute:"synopsis",
    value:
"This plugin enumerates services enabled on a Mac OS X Server host or
a host running OS X Server."
  );
  script_set_attribute(
    attribute:"description",
    value:
"By connecting to the remote host via SSH with the supplied
credentials, this plugin queries the Mac OS X Server administrative
daemon and enumerates services currently running on the system."
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Review the list of services enabled and ensure that they agree with
your organization's acceptable use and security policies."
  );
  script_set_attribute(attribute:"risk_factor", value:"None" );
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/11/22");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apple:mac_os_x_server");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2010-2022 Tenable Network Security, Inc.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/MacOSX/Version");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("ssh_func.inc");
include("macosx_func.inc");



if(sshlib::get_support_level() >= sshlib::SSH_LIB_SUPPORTS_COMMANDS ||
    get_one_kb_item('HostLevelChecks/proto') == 'local')
  enable_ssh_wrappers();
else disable_ssh_wrappers();

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

os = get_kb_item("Host/MacOSX/Version");
if (!os) audit(AUDIT_OS_NOT, "Mac OS X");


# Get the system version.
version = "";

# nb: OS X Server is an external app starting with 10.7.
if (ereg(pattern:"Mac OS X 10\.[0-6]([^0-9]|$)", string:os))
{
  cmd = '/usr/sbin/system_profiler SPSoftwareDataType';
  buf = exec_cmd(cmd:cmd);
  if (isnull(buf)) exit(1, "Failed to run '"+cmd+"'.");

  foreach line (split(buf, keep:FALSE))
  {
    match = eregmatch(pattern:"^ +System Version: (.+)$", string:line);
    if (match)
    {
      version = match[1];
      break;
    }
  }
  if (!strlen(version)) exit(1, "Failed to extract the System Version from the output of '"+cmd+"'.");

  # eg, "Mac OS X Server 10.6.8 (10K549)"
  if ("Mac OS X Server" >!< version) exit(0, "The host is not running Mac OS X Server.");
}
else 
{
  plist = "/Applications/Server.app/Contents/Info.plist";
  cmd = 
    'plutil -convert xml1 -o - \'' + plist + '\' | ' +
    'grep -A 1 CFBundleShortVersionString | ' +
    'tail -n 1 | ' +
    'sed \'s/.*string>\\(.*\\)<\\/string>.*/\\1/g\'';
  version = exec_cmd(cmd:cmd);
  if (!strlen(version)) audit(AUDIT_NOT_INST, "OS X Server");

  # eg, "2.1.1"
}


kb_base = 'MacOSX/Server/';
set_kb_item(name:kb_base+'Version', value:version);


# Get a list of services.
cmd = 'serveradmin list';
buf = exec_cmd(cmd:cmd);
if (!buf) exit(1, "Failed to run '"+cmd+"'.");

svcs = "";
foreach line (split(buf, keep:FALSE))
{
  if (
    ereg(pattern:"^[a-zA-Z0-9]+$", string:line) &&
    "accounts" != line &&
    "config" != line &&
    "filebrowser" != line &&
    "info" != line
  ) svcs += " " + line;
}
if (!svcs) exit(1, "'serveradmin list' output failed to list any services that can be queried: " + buf);


cmd = 'for s in ' + svcs + '; do serveradmin status $s; done';
buf = exec_cmd(cmd:cmd);
if (isnull(buf)) exit(1, "Failed to run '"+cmd+"'.");

info = "";
foreach line (split(buf, keep:FALSE))
{
  if (match = eregmatch(pattern:'^([^:]+):state *= *"?([^"]+)', string:line))
  {
    svc = match[1];
    status = match[2];
    set_kb_item(name:kb_base+svc+"/Status", value:status);
    info += '  - ' + svc + crap(data:" ", length:15-strlen(svc)) + ' : ' + status + '\n';
  }
}
if (!info) exit(1, "'serveradmin list' output does not contain any service info: " + buf);


# Report findings
if (report_verbosity > 0) security_note(port:0, extra:'\n'+info);
else security_note(0);
