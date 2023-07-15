#TRUSTED 0d28f072ee493fb0fe4717a3020aee12fd0068ad2b7e522194b00a6346fc806771fcf2fbe22d8b1aca9d5b080707f93e8b5dd18e193ca16b207e4f49203f7dff3dc90e60f880cbe214f1df1c55ea168421eb0de5901381900975733639c8478c430db24a2f1bfe7d2e121772fd359e03bc22d7d4f10738b5676bbbfc12a9eeca901a64c52883d56e1a77411d458d0d203fd3ef96e08d6025179bcdb3df035f1a6e3013c06f96b05bb96dacbcbcef54a6891dd336e3c583aadc09ce1a8a12fbc8caf40bcdfa800d36f71f31da970bb8b57b97393aca151f4a3d4be627fb8ffddc7caf6c44435f0673faede142938ca6afcce1d1d48730e8baf03e7db89fcfd4ceeaba346ec256421c4194c986053570fe25f4893fab23e1dd96e31060c36f2064ea6e0e64be838a5cdca65c8726a1ea0e34647c028c25430417bfbf345595265826ca4da18400fce3139e66df83b98c0c06693a1efe4ed4014b52c9d889a6424c541b4b9930fcbb81dde0b649957dbb81bdf8a890ed3f8887963a9a60a5d3f602f9109a3261f0e3c0a431b408884a006cf1d50a101baece52f4f1a0b0e4d57ca4907eb34adf9d9e5b28d8fa0f897266b3750a9222e5e2e4367a750e8663a88893ecfdb07e4747e9a1e443bad5a8449fcb064b9720a83ff3698efa940edebfc3cfe7d83cae42adfc9aee3d7c603625b4afdd3cb896a435294fb05fe6feb29794db
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(94470);
  script_version("1.38");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/06/29");

  script_xref(name:"IAVT", value:"0001-T-0550");

  script_name(english:"Cisco Firepower System Detection");
  script_summary(english:"Obtain the version of the remote Cisco Firepower System.");

  script_set_attribute(attribute:"synopsis", value:
"Cisco Firepower System is running on the remote host.");
  script_set_attribute(attribute:"description", value:
"Cisco Firepower System is running on the remote host. Firepower System
is a comprehensive management platform for managing firewalls,
application control, intrusion prevention, URL filtering, and advanced
malware protection.

It was possible to obtain version information for the Firepower System
using SSH.");
  #https://www.cisco.com/c/en/us/products/security/firepower-management-center/index.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?2b72c506");
  #https://www.cisco.com/c/en/us/td/docs/security/firepower/roadmap/firepower-roadmap.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ef16908d");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor",value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2016/11/02");

  script_set_attribute(attribute:"plugin_type",value:"local");
  script_set_attribute(attribute:"cpe",value:"cpe:/a:cisco:firepower_management_center");
  script_set_attribute(attribute:"asset_inventory", value:"True");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2004-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_ports("Services/ssh", 22);
  script_require_keys("Host/uname");

  exit(0);
}

include('audit.inc');
include('global_settings.inc');
include('misc_func.inc');
include('ssh_func.inc');
include('hostlevel_funcs.inc');
include('install_func.inc');
include('spad_log_func.inc');

if(sshlib::get_support_level() >= sshlib::SSH_LIB_SUPPORTS_COMMANDS ||
    get_one_kb_item('HostLevelChecks/proto') == 'local')
  enable_ssh_wrappers();
else disable_ssh_wrappers();

function report_and_exit(ver, build, source, vdb_ver, vdb_build, patches_ssh, interrupt_msg)
{
  local_var report, jank_ver;

  jank_ver = ver;
  if (!isnull(build))
    jank_ver += '-' + build;
  replace_kb_item(name:'Host/Cisco/firepower/Version', value:jank_ver);
  replace_kb_item(name:'Host/Cisco/firepower', value:TRUE);

  replace_kb_item(name:'Host/Cisco/firepower_mc', value:TRUE);
  replace_kb_item(name:'Host/Cisco/firepower_mc/version', value:ver);
  replace_kb_item(name:'Host/Cisco/firepower_mc/build', value:build);

  report =
    '\n  Source  : ' + source +
    '\n  Version : ' + jank_ver;    

  if (!isnull(vdb_ver))
  {
    replace_kb_item(name:'Host/Cisco/firepower_mc/vdb_version', value:vdb_ver);
    report = report + '\n  VDB Version : ' + vdb_ver;
  }

  if (!isnull(vdb_build))
  {
    replace_kb_item(name:'Host/Cisco/firepower_mc/vdb_build', value:vdb_build);
    report = report + '\n  VDB Build   : ' + vdb_build;
  }

  if (!empty_or_null(patches_ssh))
  {
    replace_kb_item(name:'Host/Cisco/firepower_mc/patch_history', value:patches_ssh);
    report = report + '\n  Patch History   :\n' + patches_ssh;
  }

  if (!empty_or_null(interrupt_msg))
    report = report + interrupt_msg;

  report += '\n';

  security_report_v4(port:0, extra:report, severity:SECURITY_NOTE);

  exit(0);
}

uname = get_kb_item_or_exit('Host/uname');

# Examples:
#  Linux firepower 3.10.53sf.virtual-26 #1 SMP Mon Feb 22 20:47:53 UTC 2016 x86_64 GNU/Linux
#  Linux am1opd1fp 3.10.45sf.westmere-17 #1 SMP Fri Oct 30 14:59:18 UTC 2015 x86_64 GNU/Linux
#  Linux firepower 3.10.53sf.virtual-53 #1 SMP Wed Nov 23 14:50:49 UTC 2016 x86_64 GNU/Linux
#  Linux Lab-asa5506 3.10.62-ltsi-WR6.0.0.29_standard #1 SMP Thu Nov 9 06:32:13 PST 2017 x86_64 x86_64 x86_64 GNU/Linux
#  Linux fpr-2100.lab.tenablesecurity.com 4.1.21-WR8.0.0.25_standard #1 SMP Tue Apr 16 12:21:06 PDT 2019 x86_64 x86_64 x86_64 GNU/Linux

##
#  If the 'uname' response does not contain 'Linux', this is probably not Cisco Firepower
#  Look for other Cisco/Sourcefire indicators, but do not exit if they are not found
##
if ( 'Linux' >!< uname)
{
  spad_log(message:'Linux string not matched in uname: ' + uname);
  audit(AUDIT_OS_NOT, 'Cisco Firepower');
}
else if ('sf' >!< uname &&
         'WR' >!< uname &&
	 '_standard' >!< uname)
{
  spad_log(message:'Firepower characteristics not matched in uname: ' + uname);
}

##
#  Additional (more reliable) verification
##
is_firepower = FALSE;

redhat_rel = get_kb_item('Host/etc/redhat-release');
slackware_rel = get_kb_item('Host/etc/slackware-version');

if ('Sourcefire Linux' >< redhat_rel ||
    'Fire Linux' >< redhat_rel ||
    'Sourcefire Linux' >< slackware_rel ||
    'Fire Linux' >< slackware_rel)
{
  spad_log(message:'Firepower matched in redhat_rel or slackware_rel');
  is_firepower = TRUE;
}

patches_ssh = get_kb_item('Host/Cisco/FTD_CLI/1/rpm -qa --last');
if (!empty_or_null(patches_ssh) &&
    'Sourcefire_Product_Family' >< patches_ssh)
{
  spad_log(message:'Firepower matched in rpm -qa --last output');
  is_firepower = TRUE;
}    

if (!is_firepower)
{
  spad_log(message:'Firepower characteristics unmatched');
  audit(AUDIT_OS_NOT, 'Cisco Firepower');
}


##
#  Firepower confirmed at this point
##
firepower_ssh = get_kb_item('Host/Cisco/os-release');
model_ssh = get_kb_item('Host/Cisco/model_conf');
vdb_ssh = get_kb_item('Host/Cisco/vdb_conf');


if (empty_or_null(patches_ssh) ||
    empty_or_null(firepower_ssh) ||
    empty_or_null(model_ssh) ||
    empty_or_null(vdb_ssh))
{

  sock_g = ssh_open_connection();
  if (! sock_g)
    audit(AUDIT_FN_FAIL, 'ssh_open_connection');

  if (empty_or_null(patches_ssh))
  {
    spad_log(message:'Executing rpm -qa --last');
    sleep(1);
    patches_ssh = ssh_cmd(cmd:'rpm -qa --last');
  }

  if (empty_or_null(firepower_ssh))
  {
    spad_log(message:'Executing cat /etc/os.conf');
    sleep(1);
    firepower_ssh = ssh_cmd(cmd:'cat /etc/os.conf');
  }
  if (empty_or_null(model_ssh))
  {
    spad_log(message:'Executing cat /etc/sf/model.conf');
    sleep(1);
    model_ssh = ssh_cmd(cmd:'cat /etc/sf/model.conf');
  }
  if (empty_or_null(vdb_ssh))
  {
    spad_log(message:'Executing cat /etc/sf/.versiondb/vdb.conf');
    sleep(1);
    vdb_ssh = ssh_cmd(cmd:'cat /etc/sf/.versiondb/vdb.conf');
  }
  ssh_close_connection();
}

# Package enumeraiton is prone to timeouts, so check if the command was interrupted
if (ssh_cmd_interrupted())
{
  interrupt_msg = '\nSSH command interrupted due to timeout or error:\n' + cmd + '\n';
  interrupt_msg += '\nPlugins will be unable to properly check installed hotfixes.\n';
}
# in case we see other 'MODEL's
# MODEL="Cisco Firepower Management Center for VMWare" -> MODEL_TYPE=CONSOLE
spad_log(message:'cat /etc/os.conf:\n' + firepower_ssh + '\n\n');
spad_log(message:'cat /etc/sf/model.conf:\n' + model_ssh + '\n\n');
spad_log(message:'cat /etc/sf/.versiondb/vdb.conf:\n' + vdb_ssh + '\n\n');
spad_log(message:'rpm -qa --last:\n' + patches_ssh + '\n\n');

# Validate that we got packages and not an error by looking for a date like "Mon Apr " from the --last, set to NULL if
# not so that this won't be reported
if (patches_ssh !~ "[A-Z][a-z]{2} [A-Z][a-z]{2} ")
{
  spad_log(message:'No date in result of rpm -qa --last, setting patches_ssh to NULL');
  patches_ssh = NULL;
}

vdb_version = pregmatch(string:vdb_ssh, pattern:"CURRENT_VERSION=([0-9.]+)\W");
if (!empty_or_null(vdb_version) && !empty_or_null(vdb_version[1]))
  vdb_version = vdb_version[1];
else
  vdb_version = NULL;

vdb_build = pregmatch(string:vdb_ssh, pattern:"CURRENT_BUILD=([0-9]+)\W");
if (!empty_or_null(vdb_build) && !empty_or_null(vdb_build[1]))
  vdb_build = vdb_build[1];
else
  vdb_build = NULL;

if ('SWVERSION' >< model_ssh && 'SWBUILD' >< model_ssh)
{
  version = pregmatch(string:model_ssh, pattern:"SWVERSION=([0-9][0-9.]+)\s*([\r\n]|$)");

  if (!isnull(version))
  {
    version = version[1];
    build = pregmatch(string:model_ssh, pattern:"SWBUILD=([0-9]+)\s*([\r\n]|$)");
    if(!isnull(build))
      build = build[1];    
    report_and_exit(ver:version, build:build, source:'SSH', vdb_ver:vdb_version, vdb_build:vdb_build, patches_ssh:patches_ssh, interrupt_msg:interrupt_msg);
  }
}
else if (
  'OSVERSION' >< firepower_ssh &&
  'OSBUILD' >< firepower_ssh
)
{
  version = pregmatch(string:firepower_ssh, pattern:"OSVERSION=([0-9][0-9.]+)\s*([\r\n]|$)");

  if (!isnull(version))
  {
    version = version[1];
    build = pregmatch(string:firepower_ssh, pattern:"OSBUILD=([0-9]+)\s*([\r\n]|$)");
    if(!isnull(build))
      build = build[1];
    report_and_exit(ver:version, build:build, source:'SSH', vdb_ver:vdb_version, vdb_build:vdb_build, patches_ssh:patches_ssh, interrupt_msg:interrupt_msg);
  }
}
audit(AUDIT_UNKNOWN_DEVICE_VER, 'Cisco Firepower');
