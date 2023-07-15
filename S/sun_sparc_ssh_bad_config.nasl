#TRUSTED 835e985d4b38d7d087a30f2a29bd45a1a09615021a8b26d67d244e4bf0933da751444159258131395d963146e055c1074674e7abd9954f60aa62a35e2c9d8e0811732ec787344ebd4a0540e63b2aef23d73d986de251d8f9b369db93be8e27b2d5b126a73140f5b5520cab2ca6899f98d91e8616027cfc362a22eb629938b8ef1718ef7e034a5b4eda9bb552dca8080ad1247e60b326c86d0eef546a2589d421f7965497e6227608f75c396bd4e771b624cc1ff3873fa2d26d4aa2762bda19b7a80b582e08e50c4a9a0fcd084901c97ed365e844b23a7c657e006a9c399374755aaea2de80c44b0a7e02b2c93b371e365d4eb719416e3a5c324b3d01754ddadc4aecbf3c24d6a60350d59e99b71d27f3374519d827bf6b0990b55a53fa4db69adcb67792ad3b247d9064487c0803f4dde6ec0f796dfb3e1330e62398619168a14f27758b5347adf03d3a168675fa05429798e2a50347ffbf54a04c7e0195f73c02b71e23061398e7d64ead63cdb651eaf00b963929cf69aa3d96ffdff32523eb4593f79254d9683d7fd249473914745bb8b26fd6c86efbbb6d1aa73465862fae08226fce6c065fd1fd2c1d0576a58957c1f88da2a74de6a7255df4b854a173c303334d42ad46fe7a202485b65827ad77769a6aa81090d38bef6424a365e8d46cb0084e5399710fca51b213a5100136b47dc64e53b13714a9f0eb7e5c26de2ae9
#TRUST-RSA-SHA256 9f7830b53075933f41088c371468c84eeb647886c9b285eb9cc9850dd05bb112e84fc6426372e072c075988b7304c31c130e7524cff983d89b3f578f8ff5d1e732ea895f068684f71c8d91c80819660932b91c958c126f58be8d53c6d78f028c88b0db6ec0bb9a167e22fb9f45135f4a94e49e66530db0bb6978980b0a30e688c6380fe510886ee3e56e9043c5f807905101f426c8149a315e5429870957111520001333ec487b2223a94e2c397a8d67a27e2196eab1fa3e11aaeaac9b6f8658df0c12d7b96491217e9ce988fdddc9d87aa254d93d44e4ca6910d74cbfb805516a84455fd9f930f598a775be488b31cda1cf60bbd08ca3023f79acf112bdbd37e9be305f49f2bd6a4c91bf3ea5bd9b3196872ef449273e12e323eb57d2279dbbf372627a6ebf02c1276c0222f44b694a0c3b92236af09ac4abd41423891b9f69836950bf121cfa674bd8f74720a05881f988904604dbcff426a1090c83a04249f03908f5b0ed1c5f9a8fc82d8176f2f8f10506c828c80a23fe6c857ad43cd2475fd04e99001165dccab1829a5d7cd4959747baaabfaf1feed7c7ad54edb7956eea5e4b9cfe603bde7a254ed2a32282a1623fd9d23867490aca5e4feb7b11c3e2890e9f1b1c43fcdcad98a9e773e5529250ffe63ed5b31fa29d62dd1e221f5d6c9bae9086959f83bcd155ac34074ea89ceac9e470864134cc6b5af6d57df4ec5b
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(69420);
  script_version("1.23");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/21");

  script_cve_id("CVE-2008-1369");
  script_xref(name:"IAVA", value:"2008-A-0025-S");

  script_name(english:"Sun SPARC Enterprise T5120 and T5220 Default Configuration Root Command Execution");
  script_summary(english:"Check for the configuration of the SPARC Enterprise Image");

  script_set_attribute(attribute:"synopsis", value:
"The remote Solaris host has a misconfigured SSH server.");
  script_set_attribute(attribute:"description", value:
"The remote Sun SPARC Enterprise Server has been mistakenly shipped with
factory settings in the pre-installed Solaris 10 image which configures
the remote SSH server insecurely. As a result, local or remote users may
leverage these misconfigurations to execute arbitrary commands with the
privileges of the root (uid 0) user.");
  script_set_attribute(attribute:"see_also", value:"https://download.oracle.com/sunalerts/1018965.1.html");
  script_set_attribute(attribute:"solution", value:
"Follow the steps in the workaround section of the advisory above");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2008-1369");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(264);

  script_set_attribute(attribute:"vuln_publication_date", value:"2008/03/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2008/03/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/08/21");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:sun:solaris");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Gain a shell remotely");

  script_copyright(english:"This script is Copyright (C) 2013-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/uname", "Host/local_checks_enabled");

  exit(0);
}

include('ssh_func.inc');
include('local_detection_nix.inc');

get_kb_item_or_exit('Host/local_checks_enabled');

if(sshlib::get_support_level() >= sshlib::SSH_LIB_SUPPORTS_COMMANDS ||
    get_one_kb_item('HostLevelChecks/proto') == 'local')
  enable_ssh_wrappers();
else disable_ssh_wrappers();

var buf = NULL;
var cmd_template = NULL;
var ret = NULL;
var uname = NULL;
var report = NULL;
var report_data = {
  'default_login_contains' : FALSE,
  'sshd_contains'          : FALSE,
  'dot_profile_contains'   : FALSE
  };

uname = get_kb_item_or_exit('Host/uname');
if ('SunOS' >!< uname)
  audit(AUDIT_OS_NOT, 'Solaris');

ret = info_connect(exit_on_fail:TRUE);
if (!ret)
  audit(AUDIT_SVC_FAIL, 'SSH', kb_ssh_transport());

# Get full path to grep util
if (!ldnix::grep_supported())
  audit(AUDIT_NOT_INST, 'grep');

grep_path = ldnix::get_command_path(command:"grep");

if (!empty_or_null(grep_path))
  grep_path = grep_path[0];
else
  audit(AUDIT_FN_FAIL, 'ldnix::get_command_path(command:"grep")', NULL);

#
# https://download.oracle.com/sunalerts/1018965.1.html
#
if (ldnix::file_exists(file:'/etc/default/login'))
  buf = ldnix::run_cmd_template_wrapper(
    template: '$1$ CONSOLE= /etc/default/login',
    args: [grep_path]);

if (!empty_or_null(buf))
  report_data['default_login_contains'] = buf;

if ('#CONSOLE=/dev/console' >!< buf) {
  ssh_close_connection();
  audit(AUDIT_HOST_NOT, 'affected');
}

buf = NULL;

if(ldnix::file_exists(file:'/etc/ssh/sshd_config'))
  buf = ldnix::run_cmd_template_wrapper(
    template: '$1$ \'^PermitRootLogin \\+yes\' /etc/ssh/sshd_config',
    args: [grep_path]);

if (!empty_or_null(buf))
 report_data['sshd_contains'] = buf;

if ('PermitRootLogin yes' >!< buf) {
  ssh_close_connection();
  audit(AUDIT_HOST_NOT, 'affected');
}

buf = NULL;

if (ldnix::file_exists(file:'/.profile'))
  buf = ldnix::run_cmd_template_wrapper(
    template: '$1$ "PS1\\|LOGDIR" /.profile',
    args: [grep_path]);

ssh_close_connection();

if (!empty_or_null(buf))
  report_data['dot_profile_contains'] = buf;

if ('PS1=\'ROOT>\'' >!< buf ||
     'LOGDIR=\'/export/home/utslog\'' >!< buf)
  audit(AUDIT_HOST_NOT, 'affected');

# Require all three in order to be marked vuln
if (!report_data['default_login_contains'] ||
  !report_data['sshd_contains'] ||
  !report_data['dot_profile_contains']
)
  audit(AUDIT_HOST_NOT, 'affected');

report =
  '\nNessus was able to detect the vulnerability by locating the ' +
  '\nfollowing items :' +
  '\n' +
  '\nIn file /etc/default/login : \n' + report_data['default_login_contains'] +
  '\nIn file /etc/ssh/sshd_config : \n' + report_data['sshd_contains'] +
  '\nIn file /.profile : \n' + report_data['dot_profile_contains'] +
  '\n';

security_report_v4(port:0, severity:SECURITY_HOLE, extra:report);
exit(0);

