#TRUSTED 155a9dfaae35ec29b2eb4506b79e83faf4a5516b2758894f0f1069c84872ca5b386406f54d84224d52dfa3604aaed2472fca91499351dd6149517696706997384c8ddee2498907387c14780572838c37c1fd514f3f57bb34a6acd7a9870e4908d6bcd92c0c4225d639d2bcb280cfa3bae4780fa20cfa1b4e662c5abb3aa960df84115a6f5912da10febf6f9be310b55a8131b037593fca5b9f0cdb0f5adad3104a6e4580028c1a32b078c88337ea68a8feb9e651b4a18c06d364c40ce75a975de55983385b377ea568b1058a6c4c0276aa62a63b2c9094f36fdb9f7729769c9759163e91e1e4ad9e939ca2a2c46c14a75d10de27972135049f9d885341bf39b4d4bbfb1d05135e1fdbe3e2ccf409e4ba086e61fa4f1e4c789f276f873cc9c4c7b94310bc58865de99bc93408907286f36cfd6b3c75194b90ab41a49fd600dee9d03eb2c53d207f45acd96e051dccd0e8c6671aaa4cba03be810aea05453f6a0b63eaea241e876adade6a934a8957fe01c12e6c32b99eadd56d8c8ba222e0cb53d3960c88939fbda4daf09056a0e58d2076bb3c59b008f7eb6d0faf746159da3ab713d4d5d2cc75a9bb917d58dc4907b340b0d0f3a14c1d527ecec8745a11de4fbb1422dc3ba4989cef1039fb98ac7bcbff332391dcb5aac9c3872b99e79d5c3bbb719c26247bc661e56b87422a17677095734ad82064e6432c7e0d8b2c5cd324
#TRUST-RSA-SHA256 22204dcab137d5137caa447ef678f7e2c25f513bb4c90a7b6fb6aa47a787df7c8496329b4762ecb33d9bedb8f1f69b1a72dc77100df80cd5beaba2c7eb17b07e00c96b1e16fdf7eea49cbe58f5274ba71635b065cb10d8f0b7288f1be961154506e23d89a0fa5090a01dc8ff5e6993c8bf2dd70e0d5f0c2faf0597c5a5bd6fcec114aa33fea5a7afbcc3ab7a0924751116737f7c52c09cca8d8b7b085b6675f655649c1c01f457139cb5fa1a759f0d341b29c7df1cbdf948810401f4a55b83a47888ab07d1da41a842627bdbd36701dfcac407c8703216b1bdc6e5359379a80421bea8c1aa93575d68fbd0cf4880545bec35e83ac76f7d4439c8f10b2fc597cff807983a2186653fff6494037b39304dfffecb1ec6fd18959a8acc352793d8f9b23ef2e3c2405587963d56dca875eeff08b075ad2e3b9fc2d8a947fc58571b591adaf91bb8fd636886a3c7e533c379b1798bbd4a08b3e197681362b147a9fc0c2c4c11a20d5b5345c8252b6ede9916abb1453f779ff1f00455cdea8015002fb1d832daaad1f0cb4fd4bcf8993558aa11f0c179c7574a8abdb52d3f50d12a4ff5c49997d1d01f9272fd3ea6af6123183adbbf63e9d48c2111c98860602876a9b580c7dd336f72ea9694e4e01181139550afff37d9f6e362f949268a01d1742dcca368fc133fb308d65f05180a3d89afd947723eefdf3460d3932f8f00283eba12
#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include("compat.inc");

if (description)
{
 script_id(15878);
 script_version("1.24");
 script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/01");

 script_name(english:"Hydra: MS SQL");
 script_summary(english:"Brute force MS SQL authentication with Hydra");
 
 script_set_attribute(attribute:"synopsis", value:
"It may be possible to determine MS SQL passwords through brute
force." );
 script_set_attribute(attribute:"description", value:
"This plugin runs Hydra to find MS SQL passwords by brute force. 

To use this plugin, enter the 'Logins file' and the 'Passwords file'
under the 'Hydra (NASL wrappers options)' advanced settings block.");
 script_set_attribute(attribute:"solution", value:"Change the passwords for the affected accounts.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_attribute(attribute:"cvss_score_source", value:"manual");
 script_set_attribute(attribute:"cvss_score_rationale", value:"No CVE available for this vulnerability.");

 script_set_attribute(attribute:"plugin_publication_date", value:"2004/12/01");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_set_attribute(attribute:"thorough_tests", value:"true");
 script_end_attributes();

 script_category(ACT_MIXED_ATTACK);
 script_copyright(english:"This script is Copyright (C) 2004-2023 Tenable Network Security, Inc.");
 script_family(english:"Brute force attacks");

 script_dependencies("hydra_options.nasl", "find_service1.nasl", "mssqlserver_detect.nasl", "mssql_blank_password.nasl");
 script_require_keys("Secret/hydra/logins_file", "Secret/hydra/passwords_file", "/tmp/hydra/force_run");
 script_require_ports("Services/mssql");
 script_timeout(30*60);

 exit(0);
}

if (!defined_func("script_get_preference_file_location")) exit(0);
if ((!find_in_path("hydra")) && (!file_stat(nessus_get_dir(N_STATE_DIR) + '/feed_build')))
{
  exit(0, "Hydra was not found in '$PATH'.");
}

include('debug.inc');
include('misc_func.inc');

var force = get_kb_item('/tmp/hydra/force_run');
if (! force) exit(0, "Neither 'thorough_tests' nor 'force_run' is set.");

var logins = get_kb_item("Secret/hydra/logins_file");
if (isnull(logins)) exit(0, "No Hydra logins file.");

var port = get_service(svc:"mssql", exit_on_fail:TRUE);         # port = 1433?
if (get_kb_item('MSSQL/blank_password/'+port)) exit(0, 'The MS SQL server listening on port ' +port+ ' has a blank password.');

# We should check that the server is up & running

var timeout = get_kb_item('/tmp/hydra/timeout'); timeout = int(timeout);
var tasks = get_kb_item('/tmp/hydra/tasks'); task = int(tasks);

var empty = get_kb_item('/tmp/hydra/empty_password');
var login_pass = get_kb_item('/tmp/hydra/login_password');
var exit_asap = get_kb_item('/tmp/hydra/exit_ASAP');
var tr = get_kb_item('Transports/TCP/'+port);

if (get_kb_item('/tmp/hydra/service/mssql')) svc = 'mssql';
else if (get_kb_item('Hydra/services')) exit(1, "The installed version of Hydra does not support the 'mssql' service.");
else exit(1, 'Failed to get the list of services that the installed version of Hydra supports.');

var i = 0;
var argv;
argv[i++] = 'hydra';
argv[i++] = '-s'; argv[i++] = port;
argv[i++] = '-L'; argv[i++] = logins;

var s = '';
if (empty) s = 'n';
if (login_pass) s+= 's';
if (s)
{
  argv[i++] = '-e'; argv[i++] = s;
}
var passwd = get_kb_item('Secret/hydra/passwords_file');
if (passwd)
{
 argv[i++] = '-P'; argv[i++] = passwd;
} else if (! s)
 exit(1, 'No Hydra passwords file.');

if (exit_asap) argv[i++] = '-f';
if (tr >= ENCAPS_SSLv2) argv[i++] = '-S';

if (timeout > 0)
{
  argv[i++] = '-w';
  argv[i++] = timeout;
}
if (tasks > 0)
{
  argv[i++] = '-t';
  argv[i++] = tasks;
}

argv[i++] = get_host_ip();
argv[i++] = svc;

set_kb_item(name:'Hydra/' +svc+ '/' +port+ '/cmd_line', value:join(argv));

var errors = make_list();
var report = '';
var results = pread_wrapper(cmd:'hydra', argv:argv, nice:5);

# Debugging : log command and output
var full_cmd = get_kb_item('Hydra/mssql/' +port+ '/cmd_line');
dbg::log(src:SCRIPT_NAME, msg:'\nCommand:\n' + '--------\n' + full_cmd + '\n'
                              + '\nResult:\n' + '--------\n' + results + '\n'); 

var line, v1, l1, v2, l2, p2 ;
foreach var line (split(results, keep:FALSE))
{
  # first check for errors and move on if found
  if (line =~ "^(Error: |Sorry, hydra)")
  {
    errors = make_list(errors, line);
    continue;
  }
  # found valid username that does not require a password
  v1 = pregmatch(string: line, pattern: "login:[\s]([^\s]*)$");
  if (!isnull(v1))
  {
    l1 = chomp(v1[1]);
    report = strcat(report, 'login: ', l1, '\tpassword: (NULL)\n');
  }
  else # (v1 == NULL) valid username/password found 
  {
    v2 = pregmatch(string: line, pattern: "host:.*login: *(.*) password: *(.*)$");
    if (!isnull(v2))
    {
      l2 = chomp(v2[1]);
      p2 = chomp(v2[2]);
      report = strcat(report, 'login: ', l2, '\tpassword: ', p2, '\n');
    }
  }
}

if (report) security_hole(port:port, extra:'\nHydra discovered the following MS SQL credentials :\n\n' + report);

if (max_index(errors) > 0)
{
  msg = '';
  n = 0;
  foreach var error (list_uniq(errors))
  {
    n++;
    if (n < 20) msg = strcat(msg, error, '\n');
  }

  set_kb_item(name:"Hydra/errors/"+svc+"/"+port, value:n);
  set_kb_item(name:"Hydra/error_msg/"+svc+"/"+port, value:msg);

  exit(1, "One or more errors occurred while running Hydra against the MS SQL server listening on port "+port+".");
}

if (!report) exit(0, "Hydra did not discover any credentials for the MS SQL server listening on port "+port+".");
