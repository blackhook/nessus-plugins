#TRUSTED 7c030040e1d4fee16913cd5863417f7d53b9c2fd4ea7440e5333a3823ae50b9e8f2cfa975b1de4e3819435d6ee0168e578c059783474961d7f564bd18779584b62a5f4956f02e1bfbde2f3aa6b2603bcd9a9e4cf86de4ebe3c3ffc149f0391a413125631ed5ab222138a73200ad29df603a134f0bed7925f46b241ca232bb7037a1a26089dff7403c5de6e45305f08cb59b9f78462a578b01d39305d9cbe1f69cf318758cdd6231afb1631b47685d802f60ae5baac0a1d9e26011f2c834e5ad63d06edba8cdad8bbb78b8fbc8918ee141ea978101622597951dca7d35aff0a0b8c56a023929ba4a2cf1d92aa75350fa511168bcff2d6215558e3958656b5d226e0642a46530810afc086cca71cf1a49fa54d3bf8572ebc001a9a3869b58095f4aadf9655a8144b433d299124241194a50d2ead9d295b411586117f2620245433227bcb4582edd163d9fca4103b1f9d47f191a842905823122a5f73fd372bb10aac57af11903df2468fc79139c31861ee2faacb256bee91d36b293029ae55301dd577ffcb0d4529314186de358d18199f7a562f2a0380134b196ca1b4d76fa05eea070d840b5d7844e8cb45518997c2c7266361db01256542120e1f272d3d1f74ae945cfa3c492cd394d7769d42fef8ac94de69d1516d60527e3499d4e3d8f2eb688fc5d06528f82c262a606f78dd1afab54535b9321c108f75d9677b06622175
#TRUST-RSA-SHA256 8b1f9dba6e4a389562853c40ebf49cf6e9338f8d08cc94aeeb4931638fc7668298b16434e87a8e2fb966347cd13dcef5c9e2c6cd751cd931038b574e52a298e59467de46a550835d546addfa225d4601241745c5274d8535be1d064108f71141f815cb624511fba95816cfa6bcf6370177191058020ea2692061b374a60a7fe102b6504f6c8c31666bc5efaf85b47477b4263a1eff5927d4464d7013d513b950b22f29213e787313088ebaf469492cb66d0e88ad8afadaaf3908cb2b772c1e75d9f0178aa6fbd28c3e8d1dd0cdb9c63427e50a065a2c68f523add05e471372c60bddc8f63e54cbaf64b01fd1812d98b4c4c026cd38eaba8812a62e4bfacb5a6e5aef0a091e5264aaae502e09a497ee48cc3bb09c441a62ea1a520b0b0b60b40e8f78ebacdc6869e2be134b30d346e1b8207828caf1218757dfdd7e6358e9005aa4def516f56e0796018d3cafbc82fc0798c3275963a0f7745b7662fef451ba68aacdfd2d2983755554512e8af4d483cfce925f942c45b3ea1a098232d34b0c914b87ba9b10a36fb4869520c01ea1e7757cf0693947060c4895c43dd8b54fc891bf4e2b2b3a38272be825d870dbdd3b0c0ea0e28d8b50b323f5c738a0d0a2118f0891aef03bbb600e1b7f90ec6d357b70033b9be0559b59bb5dedc94dffcf611613088c1acee6ba6708dc085a843d7e5adc43e7aab983abf2d5e268e594e30ace
#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include("compat.inc");

if (description)
{
 script_id(15884);
 script_version("1.20");
 script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/01");

 script_name(english:"Hydra: SMB");
 
 script_set_attribute(attribute:"synopsis", value:
"It may be possible to determine SMB passwords by brute force.");
 script_set_attribute(attribute:"description", value:
"This plugin runs Hydra to find SMB accounts and passwords by brute
force, using the smb2 module.  

To use this plugin, Hydra must be installed in the same machine as your scanner.

To configure the a scan policy to use Hydra, go to 'Assessment > Brute Force' and check the 'Always enable Hydra (slow)' 
option, then apply the relevant settings.");
 script_set_attribute(attribute:"see_also", value:"https://www.kali.org/tools/hydra/");
 script_set_attribute(attribute:"solution", value:
"Always use unique, complex passwords. Change the passwords for the affected accounts.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:L/I:L/A:L");
 script_set_attribute(attribute:"cvss_score_source", value:"manual");
 script_set_attribute(attribute:"cvss_score_rationale", value:"Score based on analysis of the potential security risk.");

 script_set_attribute(attribute:"plugin_publication_date", value:"2004/12/01");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_add_preference(name: "Interpret passwords as NTLM hashes", 
	value: "no", type: "checkbox");

 script_category(ACT_DESTRUCTIVE_ATTACK);	# risk of accounts lock out
 script_copyright(english:"This script is Copyright (C) 2004-2023 Tenable Network Security, Inc.");
 script_family(english:"Brute force attacks");

 script_dependencies("hydra_options.nasl", "find_service1.nasl", "doublecheck_std_services.nasl");
 script_require_keys("Secret/hydra/logins_file", "Secret/hydra/passwords_file", "/tmp/hydra/force_run");
 script_require_ports("SMB/transport");
 script_timeout(30*60);

 exit(0);
}

if (!defined_func("script_get_preference_file_location")) exit(0);
if ((!find_in_path("hydra")) && (!file_stat(nessus_get_dir(N_STATE_DIR) + '/feed_build')))
{
  exit(0, "Hydra was not found in '$PATH'.");
}

include('debug.inc');

var force = get_kb_item("/tmp/hydra/force_run");
if (! force) exit(0, "Neither 'thorough_tests' nor 'force_run' is set.");

# Because of accounts lock out 
if (safe_checks()) exit(0, 'safe_checks is set (risk of accounts lock out).');

var logins = get_kb_item('Secret/hydra/logins_file');
if (isnull(logins)) exit(0, 'No Hydra logins file.');

var port = get_kb_item('SMB/transport'); port = int(port);
if (!port) exit(0, 'No SMB server was detected.');
if (!get_port_state(port)) audit(AUDIT_PORT_CLOSED, port);

var timeout = get_kb_item('/tmp/hydra/timeout'); timeout = int(timeout);
var tasks = get_kb_item('/tmp/hydra/tasks'); task = int(tasks);

var empty = get_kb_item('/tmp/hydra/empty_password');
var login_pass = get_kb_item('/tmp/hydra/login_password');
var exit_asap = get_kb_item('/tmp/hydra/exit_ASAP');
var tr = get_kb_item('Transports/TCP/'+port);

# check supported services
if (!get_kb_item('Hydra/services'))
  exit(1, 'Failed to get the list of services that the installed version of Hydra supports.');
  # audit(AUDIT_HYDRA_NO_SERVICES); (Work In Progress, hydra_audit.inc)

# Not using smb for service now, only smb2
var smb2 = get_kb_item('/tmp/hydra/service/smb2');
  
var svc;
if (smb2) svc = 'smb2';

else exit(0, 'The installed Hydra instance does not support the smb2 service. ' +
             'You must install the Samba client library (libsmbclient), reconfigure ' +
             'and re-install Hydra to use this plugin.');

spad_log(message:'Service selected: ' + svc);

# build command args
# i = incremental index for building the hydra command
var i, argv;

i = 0;

argv[i++] = 'hydra';
argv[i++] = '-s'; # port
argv[i++] = port;
argv[i++] = '-L'; # get the logins list
argv[i++] = logins;

# try empty passwords
var s = '';
if (empty)
  s = 'n';

# try login as password
if (login_pass) 
  s+= 's';

if (s)
  argv[i++] = '-e'; argv[i++] = s;

# get the password list
var passwd = get_kb_item('Secret/hydra/passwords_file');
if (passwd)
{
  argv[i++] = '-P'; 
  argv[i++] = passwd;
}

else if (! s)
 exit(1, 'No Hydra passwords file.');

# Stop brute forcing after the first success
if (exit_asap) 
  argv[i++] = '-f';

# set timeout
if (timeout > 0)
{
  argv[i++] = '-w';
  argv[i++] = timeout;
}

# set tasks, reccommended value is 1 for smb
if (tasks > 0)
{
  argv[i++] = '-t';
  argv[i++] = tasks;
}

# set the target and service, e.g smb2//1.2.3.4
argv[i++] = svc + '://' + get_host_ip();

# To utilize the "Interpret passwords as NTLM hashes" option, 
# we must append the value of opt to the last command 
var opt = '';
var prefs = script_get_preference('Interpret passwords as NTLM hashes');

if ('yes' >< prefs) 
{ 
  opt += '/nthash:true';
  argv[max_index(argv) -1] += opt; 
}

# build the hydra command from argv array
var command = join(argv);

set_kb_item(name:'Hydra/smb/'+port+'/cmd_line', value:command);

var errors = make_list();
var report = '';

# run command
var results = pread_wrapper(cmd:'hydra', argv:argv, nice:5);

# DEBUGGING: log command and result
spad_log(message:'\ncommand: \n' + command + '\nresult: \n' + results + '\n');

var line, v, l, p, warnings;
foreach var line (split(results, keep:FALSE))
{
  v = pregmatch(string: line, pattern: "host:.*login: *(.*) password: *(.*)$");
  if (! isnull(v))
  {
    l = chomp(v[1]);
    p = chomp(v[2]);
    report = strcat(report, 'username: ', l, '\tpassword: ', p, '\n');
    set_kb_item(name: 'Hydra/smb/'+port, value: l + '\t' + p);
  }
  else if (line =~ "^\[ERROR\]")
    errors = make_list(errors, line);
  else if (line =~ "^\[WARNING\]");
    warnings = make_list(warnings, line);
}

# DEBUGGING: record warnings
var w, w_msg, warning;
if (max_index(warnings) > 0)
{
  w_msg = '';
  w = 0;
  foreach var warning (list_uniq(warnings))
  {
    w++;
    w_msg = strcat(w_msg, warning, '\n');
  }
  spad_log(message:'The Hydra command produced ' + w + ' warnings; \n' + w_msg);  
}

if (report) 
  security_report_v4(port:port, severity:SECURITY_HOLE, extra:report);

var msg, n, error; 
if (max_index(errors) > 0)
{
  msg = '';
  n = 0;
  foreach var error (list_uniq(errors))
  {
    n++;
    if (n < 20) msg = strcat(msg, error, '\n');
  }
  set_kb_item(name:'Hydra/errors/smb/'+port, value:n);
  set_kb_item(name:'Hydra/error_msg/smb/'+port, value:msg);
  exit(1, 'One or more errors occurred while running Hydra against the SMB server listening on port '+port+'.');
}

if (!report) exit(0, 'Hydra did not discover any credentials for the SMB server listening on port '+port+'.');
