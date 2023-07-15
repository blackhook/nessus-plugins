#TRUSTED 777e40c9d8af36476a7611f25c48007ea2cc0ec9e16bcfd77ec2061ae8350d9f63c5603f63ad323af201ed9e55f38c05dcaa4d0d1da6d63036a9f9a5afcbb0606c1ec4dec50fd24d9d37fb8b009d51fd31d595a9ce64353febea2188dfd863ed8a6d645b071c6e6d3bfc1d467c1f5f2f194ce08385c9a6ca1988d91c0ba2b7a136523c6e6fe43448a88e36fb6125bf122e25f1f1674dd1e02aa93f6308e7d677cfb0f2304b7f983919d34c5ba6607e2f44e817cfc287ec2c10b1218b2256dfe0675fe71038f6dfe4e11ee234d1867c1c0b17803d7298a504542bafda7885597961678bbadd83fbf57c54835dc9bd55d114c8a7a54719e5de5b87fba60e969f4431cc5075910404bce839cac15ebcf85e6b02bb7ef3f38a49435b0e951ccd15f356181d331d7787ac3aedb164ed703c71223d4b23707829c300d52b4689424df2ff4f5c6a433d74fb5f1abf447ee6c02e3b6c19f0562c86da064f5888c2c98a18a3f59b8559776f172483b3cf8c7e15fa63fb7d80918ae11f89afc248307d1542a2227ee6ab06e87725e5aefc242a00d49da28b31844fffdb7a224b06beb9ec1db9b3a585c64799f1bb40c893b426941078975b565268a4cdd61e31d72db68dafaa08acaa422ab30f02a6d026e06ba08cee595b049bc73e25d66cd8b7d9e8f30a3386eb669510ae3868f25b1970d365450b8ae9ad497afdbcbc6121977671e9d3
#%NASL_MIN_LEVEL 70300

#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include("compat.inc");

if (description)
{
  script_id(152741);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/09/19");

  script_name(english:"Unix Software Discovery Command Checks");
  script_summary(english:
"Checks commands used for software that is not managed by the OS.");
  script_set_attribute(attribute:"synopsis", value:
"Runs local commands over SSH that are used by plugins to find and
characterize software that is not managed by the operating system.");

  script_set_attribute(attribute:"description", value:
"Nessus plugins run OS commands locally on the target host to discover
and characterize software that is not managed by the target operating
system.  This plugin runs those commands over SSH to determine whether
there is any problem that might prevent the successful discovery of
unmanaged software installations.

    Examples:
      find
      cat
      grep
      ls

Problems that could interfere with the discovery of unmanaged
software include scanning with weak permissions, incorrect chroot or
sudo configuration, and missing or corrupt executables."
);

  script_set_attribute(attribute:"risk_factor", value:"None");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/08/23");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2021-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info2.nasl");
  script_require_ports("Host/FreeBSD/release", "Host/Solaris/Version", "Host/Solaris11/Version", "Host/AIX/version",
                       "Host/HP-UX/version", "Host/Linux", "Host/NetBSD/release", "Host/OpenBSD/release",
                       "Host/MacOSX/Version");

  script_require_keys("Host/uname");

  exit(0);
}

include('ssh_compat.inc');
include('ssh_lib.inc');
include('spad_log_func.inc');

##
# Tests the output of executing a command sequence against the
# expected result.
#
# Notes:  expect_error considers error output when exec mode is used.
#         In cases where the same pattern is used for both error and
#         command output, expect_error is set to TRUE.
##
function test_command(cmd, pattern, expect_error)
{
  if(isnull(cmd) || isnull(pattern))
    return FALSE;

  if(isnull(expect_error))
    expect_error = FALSE;

  var res = info_send_cmd(cmd:cmd);
  var err = sshlib::ssh_cmd_error_wrapper();
  sshlib::ssh_cmd_clear_error();

  #If the scan didn't use a shell handler and we expect an error
  if(expect_error && !res && err)
  {
    res = strip(err);
    err = NULL;
  }

  #Strip newlines in output. Output is split due to terminal width on some systems
  res = ereg_replace(string:res, pattern:"[\r\n]+", replace:"");

  if(res && preg(string:res, pattern:pattern, multiline:TRUE))
  {
    spad_log(message: "Successfully executed '" + cmd + "' on the target host and received the expected result '" + res + "'.");
    return TRUE;
  }

  spad_log(message: "Attempted to execute '" + cmd +
                    "', but received an unexpected result: '" + serialize(res) +
                    "' , error: '" + serialize(err) + "'.");

  var b64_cmd = base64(str:cmd);
  var b64_res = NULL;
  if(!isnull(res))
    b64_res = base64(str:res);

  if(isnull(b64_cmd))
    #Only one of these will ever get set, but it can help with debugging.
    replace_kb_item(name:"Host/unmanaged_software_checks/Failures/<error encoding command>", value:"<none>");
  else if(isnull(res) || isnull(b64_res))
    replace_kb_item(name:"Host/unmanaged_software_checks/Failures/" + b64_cmd, value:"<none>");
  else
    replace_kb_item(name:"Host/unmanaged_software_checks/Failures/" + b64_cmd, value:b64_res);

  return FALSE;
}

get_kb_item_or_exit("Host/uname");

var host;
if(!isnull(get_kb_item("Host/FreeBSD/release")) ||
   !isnull(get_kb_item("Host/NetBSD/release")) ||
   !isnull(get_kb_item("Host/OpenBSD/release")) ||
   !isnull(get_kb_item("Host/Linux")))
  host = "linux";

if(!isnull(get_kb_item("Host/Solaris/Version")) ||
   !isnull(get_kb_item("Host/Solaris11/Version")))
  host = "solaris";

if(!isnull(get_kb_item("Host/AIX/version")))
  host = "aix";

if(!isnull(get_kb_item("Host/HP-UX/version")))
  host = "hpux";

if(!isnull(get_kb_item("Host/MacOSX/Version")))
  host = "mac";

if(!host)
 audit(AUDIT_HOST_NOT, "Linux, Solaris, AIX, HP-UX or a known BSD distro");

if(sshlib::get_support_level() >= sshlib::SSH_LIB_SUPPORTS_COMMANDS ||
    get_one_kb_item('HostLevelChecks/proto') == 'local')
  enable_ssh_wrappers();
else disable_ssh_wrappers();

info_connect(exit_on_fail:TRUE);

replace_kb_item(name:"Host/unmanaged_commands_supported", value:TRUE);

#################################
# find matching
#################################
var find_expect, find_expect_err;
find_expect = "\.";
find_expect_err = FALSE;
if(host == "hpux" || host == "solaris")
{
  find_expect = "find: bad option -maxdepth";
  find_expect_err = TRUE;
}
else if(host == "aix")
{
  find_expect = "find: [^\s]+ -maxdepth is not a valid option.";
  find_expect_err = TRUE;
}

#################################
# which matching
#################################
var which_expect, which_expect_err;
which_expect = "(/which|which \(\))|which: shell built-in";
which_expect_err = FALSE;
if(host == "mac")
{
  which_expect = NULL;
}

#################################
# cat matching
#################################
var cat_expect, cat_expect_err;
cat_expect = "(?:cat \(GNU coreutils\) [\d.]+|cat: illegal option --|cat: invalid option --)";
cat_expect_err = TRUE;
if(host == "aix")
  cat_expect = "cat: Not a recognized flag: -";

#################################
# grep matching
#################################
var grep_expect, grep_expect_err;
grep_expect = "^(?:GNU )?grep(?: \((?:GNU|BSD) grep[^)]*\))? [\d.]{3}";
grep_expect_err = FALSE;
if(host == "aix")
{
  grep_expect = "grep: Not a recognized flag: V";
  grep_expect_err = TRUE;
}
else if(host == "solaris" || host == "hpux")
{
  grep_expect = "grep: illegal option -- V";
  grep_expect_err = TRUE;
}

#################################
# readlink matching
#################################
var readlink_expect, readlink_expect_err; 
readlink_expect = "(?:readlink \(GNU coreutils\)|readlink: illegal option --)";
readlink_expect_err = TRUE;
if(host == "mac" || host == "solaris" || host == "aix" || host == "hpux")
  readlink_expect = NULL;

#################################
# unzip matching
#################################
var unzip_expect, unzip_expect_err;
unzip_expect = "(?:UnZip \d\.\d|Usage: unzip)";
unzip_expect_err = TRUE;
if(host == "mac" || host == "aix")
{
  unzip_expect = NULL;
}

#################################
# strings matching
#################################
var strings_expect, strings_expect_err;
strings_expect = "(?:GNU strings|strings \()";
strings_expect_err = TRUE;

if(host == "aix" || host == "hpux" || host == "solaris")
  strings_expect = "Usage: strings \[";
else if(host == "mac")
  strings_expect = NULL;

#################################

# Test all commands, excluding "cat"
var test_cmds = test_command(cmd:"find . -maxdepth 0 -type d", pattern:find_expect, expect_error: find_expect_err) &&
            test_command(cmd:"ls -d .", pattern:"\.", expect_error: FALSE) &&
            (isnull(which_expect) || test_command(cmd:"which which", pattern:which_expect, expect_error: which_expect_err)) &&
            test_command(cmd:"grep -V", pattern:grep_expect, expect_error:grep_expect_err) &&
            (isnull(readlink_expect) || test_command(cmd:"readlink --version", pattern:readlink_expect, expect_error: readlink_expect_err)) &&
            (isnull(unzip_expect) || test_command(cmd:"unzip -v", pattern:unzip_expect, expect_error: unzip_expect_err)) &&
            (isnull(strings_expect) || test_command(cmd:"strings -v", pattern:strings_expect, expect_error: strings_expect_err)) &&
            (host != "mac" || (test_command(cmd:"plutil -help", pattern:"plutil: \[", expect_error:TRUE) &&
                                test_command(cmd:"sed -x", pattern:"sed: illegal option -- x", expect_error:TRUE) &&
                                test_command(cmd:"tail -x", pattern:"tail: illegal option -- x", expect_error:TRUE) &&
                                test_command(cmd:"awk", pattern:"usage: awk \[", expect_error:TRUE)));


# Test "cat" command if scanning over SSH
if (info_t == INFO_SSH)
{
  var cat_cmd = test_command(cmd:"cat --version", pattern:cat_expect, expect_error:cat_expect_err);
  test_cmds = test_cmds && cat_cmd;
}

if(test_cmds)
{
  spad_log(message: "Scanning localhost : All unmanaged software commands ran and returned the expected result.");
  replace_kb_item(name:"Host/unmanaged_software_checks", value:TRUE);
}

ssh_close_connection();
exit(0, "This plugin does not report.");
