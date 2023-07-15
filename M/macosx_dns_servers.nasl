#TRUSTED 4a28dd66d92bd43b46be057f0a259577d8b0194b1dab878b316580e9917f4a91421651a3bf176e5309849209ec7bda94712bf3596cd21acd325c2efa8e2172014629d5bf766f71d1f43f4a48334b5e047030ee6c0bb172a73ea8a467a59e46e1e145a3c46691cffcc7874a5c65e4eb2c3a3056a89f99b4a4baebf8beee341606db8e27f281d64950af29064a106249c0e6c353e28af46c685f59795763772a9e1eae5ce746a9861a1c3fc3808db9e0e32823512c5d4bc1da08071e8cab9d7dddbd4d64ca12c7d4b9524499a6e90bf88917b4d56e6e9a919901aef9daac085e3acc24e4fc358f497b224b6fc801d6a1236f97195f9b2907bd2ee5a32561979b64d9b8c94205c70735e2e4577208ed9778d928949eaa093f0895ae6b28631e7c1f9f3e6c79575ec3206a60fb09a2e769f108fcca836e873786649db4369abf458c67a21650a63ddfa0abb86b1d3fef24d664254a0dd7c35031532d09a51cb96c0276062c34d60a83524c84cac44211a05ece77e8c382716a68059b2325ceeb19e05e72e88b4fa040e5481fa1711b2db650da8651e1a78704eec828f554025814fa7c4dcfc13ebf52d30efca01725e0217681c1f62490674ae35130fedec5972590414b12f5b2b206595befea202ea7f75d713bfd12d2e4728327a0e4a8e5571c4f98085daba926f26ace9f718a7de5c7cc3085d63451d0cf4ae37d39a6c898373e
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");


if (description)
{
  script_id(58180);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/06/29");

  script_name(english:"Mac OS X DNS Server Enumeration");
  script_summary(english:"Looks in resolv.conf to see which DNS servers are in use");

  script_set_attribute(
    attribute:"synopsis",
    value:
"Nessus enumerated the DNS servers being used by the remote Mac OS X
host."
  );
  script_set_attribute(
    attribute:"description",
    value:
"Nessus was able to enumerate the DNS servers configured on the remote
Mac OS X host by looking in /etc/resolv.conf."
  );
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2012/03/01");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:apple:mac_os_x");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2012-2022 Tenable Network Security, Inc.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/MacOSX/Version");

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("ssh_func.inc");
include("macosx_func.inc");


if(sshlib::get_support_level() >= sshlib::SSH_LIB_SUPPORTS_COMMANDS ||
    get_one_kb_item('HostLevelChecks/proto') == 'local')
  enable_ssh_wrappers();
else disable_ssh_wrappers();

get_kb_item_or_exit("Host/local_checks_enabled");
get_kb_item_or_exit("Host/MacOSX/Version");

nameserver_file = '/etc/resolv.conf';
cmd = '/bin/cat ' + nameserver_file;
output = exec_cmd(cmd:cmd);
if (!strlen(output)) exit(1, "Failed to get the version of Safari.");

dns_servers = make_list();

foreach line (split(output, sep:'\n', keep:FALSE))
{
  # extract name servers, ignoring commented lines
  match = eregmatch(string:line, pattern:"^[^#;]*nameserver ([0-9.]+)");
  if (isnull(match)) continue;

  dns_servers = make_list(dns_servers, match[1]);
}

report = NULL;

foreach server (dns_servers)
{
  set_kb_item(name:'resolv.conf/nameserver', value:server);
  report += server + '\n';
}

if (isnull(report))
  exit(0, "No DNS servers were found in '" + nameserver_file + "'.");

if (report_verbosity > 0)
{
  report = '\nNessus found the following nameservers configured in ' + nameserver_file + ' :\n\n' + report;
  security_note(port:0, extra:report);
}
else security_note(0);

