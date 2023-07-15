#TRUSTED 90ee39a11eb26769be26d66c75454231d542d959f44a259be25e4705202ab688c106d345d79273d06c7ba4465c05cd627fb887c0f163cd0d94c06374aec2e13c0c50ac73ec1f8698174fa2f67ca28c262bbe73086c99c08d4435dde974a0260774d90c7e297ed5b75518a8aa64620064221e83b9ff3db538794676c0f483bade337a4afbc2dc9257cbd95de09b5a20afd8150e2a44f78dd7a36c80420aa95f0e3c3dd6c5b0e0203f69b63bf1ad54354a5f63d80064b3e6fd841f82afdd4d4485be1cfcfc6d1d9be522e75271f6a9da84089bab56165d70fa07378d6f888dd53f9840992d17f5e499bd232500fca643e5df3e284eeba0b883f36e97d92c17fd98779935a36bd128935f406839c81982706c991e17ac5236ce0e7edc6e18a1e50b79533e5d8219aae4527413187a42786a81da063c7caf6cc12f4b47c7611b15e3fdd926ccfa4fc3e8baf1157f304a1da14cbea72cf741eb27bceaea204bec1453b58665cd008345310c4ceb959226ace6ca2cd616544d59822f293008f9ab7e966677069c5f4f8f3cc4631c9cae975889763703c47a375ec3130b030ef3cace8eb33668c831b401146a42305d43c0b349953d92ba6ac644a737e5794d866084a22bb7c2ade7afe5f263d4afb40f260bfbc89a24eb3f318b86db6ea0bd293b1989c4a0bb8d87cac52d9b4325dbf9e9bb4ea6d8e850b9985225dbeeb507672fd7fc
#TRUST-RSA-SHA256 37422590924a4eed5b66fecfdc9a2d02adbab8ba301b6cd90398e11554fe3e4183f93d9cf447621e8d52fee44c9d8c9e7b9a38bb18009362549dd6971898aac5926a80dae0d3fa3e55ef022a9011d2f77dc60ef30703dbfeb18a9226d00d1ada64e3d81e350b054733cc2a933802a7a5fc1b841cd3a238d2c8278b64cbe64543f099d25db1905a3dd672ee20daf1d05fd6daefdba25d96bf63e35d47b43bdc7ff6d62bec973797090fdb2759d87bd6e868af0df988c32a346cd9d4a605108e109c2b3fda16fd1565badb4bd2bfd87ec85c72e5ab33f3395ce31bfc559861767f341a139d19074536d3766021519d1b474fc794c268c595791ef9449aeb6dfe0a3748c941db9f9ff8f2961d98965498bd332e6699b4f043f92886a836f60dfb11d0b6c2333bbf4f1fb874738753ac33382f2011dd465e2e0f9b4e6098e873304300bdbcba607495b963884d2d1ff1bdb3e4a3f9b779ef310cc3aed590e8dede73575f426bb03f18e5502f51e78a68ef9ecf0d8ad541353f3699b446241f832d6a810210c3b7498d57308773649ea854c0eb9d8b667e81c1eb5016783679cdf2856932618919a92d4c17fff12e40af90b4d1e4629e3da0340a05c21db62b7ab9976ac3465aa06af46a397fa18b13c43be8433fda172f2b9cae2ea99755a9bdda2b19b76410b0773ebea4cce9809a67585297e255c606a3e56d3f409f673dedbba3
#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include("compat.inc");

if (description)
{
 script_id(15875);
 script_version("1.20");
 script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/01");

 script_name(english:"Hydra: ICQ");
 script_summary(english:"Brute force ICQ authentication with Hydra");
 
 script_set_attribute(attribute:"synopsis", value:
"It may be possible to determine ICQ accounts through brute force.");
 script_set_attribute(attribute:"description", value:
"This plugin runs Hydra to find ICQ accounts and passwords by brute
force. 

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

 # Currently, ICQ is not identified by find*.nasl
 script_dependencies("hydra_options.nasl", "find_service2.nasl", "external_svc_ident.nasl");
 script_require_keys("Secret/hydra/logins_file", "Secret/hydra/passwords_file", "/tmp/hydra/force_run");
 script_require_ports("Services/icq", 5190);
 script_timeout(30*60);

 exit(0);
}

if (!defined_func("script_get_preference_file_location")) exit(0);
if ((!find_in_path("hydra")) && (!file_stat(nessus_get_dir(N_STATE_DIR) + '/feed_build')))
{
  exit(0, "Hydra was not found in '$PATH'.");
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

force = get_kb_item("/tmp/hydra/force_run");
if (! force) exit(0, "Neither 'thorough_tests' nor 'force_run' is set.");

logins = get_kb_item("Secret/hydra/logins_file");
if (isnull(logins)) exit(0, "No Hydra logins file.");

port = get_service(svc:"icq", exit_on_fail:TRUE);           # port = 5190?

# We should check that the server is up & running

timeout = get_kb_item("/tmp/hydra/timeout"); timeout = int(timeout);
tasks = get_kb_item("/tmp/hydra/tasks"); task = int(tasks);

empty = get_kb_item("/tmp/hydra/empty_password");
login_pass = get_kb_item("/tmp/hydra/login_password");
exit_asap = get_kb_item("/tmp/hydra/exit_ASAP");
tr = get_kb_item("Transports/TCP/"+port);

if (get_kb_item("/tmp/hydra/service/icq")) svc = "icq";
else if (get_kb_item("Hydra/services")) exit(1, "The installed version of Hydra does not support the 'icq' service.");
else exit(1, "Failed to get the list of services that the installed version of Hydra supports.");

i = 0;
argv[i++] = "hydra";
argv[i++] = "-s"; argv[i++] = port;
argv[i++] = "-L"; argv[i++] = logins;

s = "";
if (empty) s = "n";
if (login_pass) s+= "s";
if (s)
{
  argv[i++] = "-e"; argv[i++] = s;
}
passwd = get_kb_item("Secret/hydra/passwords_file");
if (passwd)
{
 argv[i++] = "-P"; argv[i++] = passwd;
} else if (!s)
 exit(1, "No Hydra passwords file.");

if (exit_asap) argv[i++] = "-f";
if (tr >= ENCAPS_SSLv2) argv[i++] = "-S";

if (timeout > 0)
{
  argv[i++] = "-w";
  argv[i++] = timeout;
}
if (tasks > 0)
{
  argv[i++] = "-t";
  argv[i++] = tasks;
}

argv[i++] = get_host_ip();
argv[i++] = svc;

set_kb_item(name:"Hydra/"+svc+"/"+port+"/cmd_line", value:join(argv));

errors = make_list();
report = "";
results = pread_wrapper(cmd:"hydra", argv:argv, nice:5);
foreach var line (split(results, keep:FALSE))
{
  v = pregmatch(string: line, pattern: "host:.*login: *(.*) password: *(.*)$");
  if (! isnull(v))
  {
    l = chomp(v[1]);
    p = chomp(v[2]);
    report = strcat(report, 'login: ', l, '\tpassword: ', p, '\n');
    set_kb_item(name: 'Hydra/icq/'+port, value: l + '\t' + p);
  }
  else if (line =~ "^(Error: |Sorry, hydra)")
  {
    errors = make_list(errors, line);
  }
}

if (report) security_hole(port:port, extra:'\nHydra discovered the following ICQ credentials :\n\n' + report);

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

  exit(1, "One or more errors occurred while running Hydra against the ICQ server listening on port "+port+".");
}

if (!report) exit(0, "Hydra did not discover any credentials for the ICQ server listening on port "+port+".");
