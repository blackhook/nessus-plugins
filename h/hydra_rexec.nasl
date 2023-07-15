#TRUSTED 5d1e66364f8003b7432bb42bad324dbebd5eb38601b3cb00867623c2452d42a0bb73be0a00705949c67d65e1fe08e9a5fcde416ad35bc6ba9e3a633a8042a03e817b0fd43d30fcc68b43d6825088362ce6bfc665088ea7a9f1c319167cf43cdc1dedffa0b90bd39d9a7b72aaa451ef468732b8548d4e85079c528010bbabb9e2b436d90c5848fc1212a33faf56568707a737fc9f458e2ed79fbe70819e00bb5b452a0f6fca5b633c331c49accda70daaf24b348ca9199b7e73c168734d62b7f667bf183634fead695ecae494fc475186578643452d95af8aa4a8e6f4ba6e522118bddc413f0ee12a08d26174bfd5b10882aa58a2a81699a4645c5719badb894ad556409b0d6136831e443d8ef2331d8eefda33d3c62ef8247ffe23c49a7031c41f8ebce765737258e5a31a9a3e761b4ea6bd0e75d9639cbdb244247b87e61ba3bc259946b9e2505012c2810549250fe311dda7506b48b6ba2b82221a2708dc3c7a36ac328ca4c1125cfa1ab7a663191d185b3b4e1a1e9788395a7d24e66a41e7149d8c2649a530494073127e0571f6296a6c4191a609457c6ea78a3a85dee9f40bb48b389a72b6933aeb4970f3a827a1fd026b95f2d58a691ca77c21b0b91152a94614511fd34ebb5cb2c2d35cdf94fe20ae71370a58e69ce8e340330b6c933dfbf9cd6ede59e0219223b840c9284d8e9a143019d45b7225c5b8bd5d8d3a8e6b
#TRUST-RSA-SHA256 8435d73b5e541e90da33fe970f884f424d150d47bdecf27501c773dbd858cf273f08f1e00a2b035bbbfe74f8299543cbd89936a21ab9642fd0d68d155f03de7f53c1595cba0b5394d1f7e8b4dc2876c5f7d933a602266e9cca4f9652ac94be60b190e38f30a3530b926cd313170c8dad56da8f39c91f431e126efbe5bd80441b521ae565337387e74d01ea02b72bae117269af173f27a6eb754707af58800f4ea65a9aec3d02c00a9a52464005422870995d13f8b3fb78d2d98acd50e8a19eaae740f6dbb1b764c15fc3f8feafa13371e182f408b2132f9b34850dfbc44f0cedf6d9710c4e0ebf4170129c50c1ed8c32ab2506b55f31eb098d72c6111cc81878cc62528b4436dc13e6e619c57c20a614e20591174a2b5216cc7cc5cf4a022672c801cdad0275ddbfbbf28c7728461c238a6724d69d71735a6289479f16ff161fcb92c384a967a35b143e98a705fffb62fd7ff352ab8147d177acd7f8d8a5a3cb7e78f0b6414300073e5adf2b9d8d0ddcab6d3523b0b9ab8a3b42e32920b4045941888b06bb475a0f87462e612915e51401a91407812c63e4cf3434b88862b72dc8898857ecd5a18dad806f96eea042c2185cb9b9d1673af70f68af65f2827b053c8bfb5000265df03a49ad24508b5f1c7e918dee5cfc59a78f5d7f86408288376fa1550d0760572f35eed2ffce4b81f1e89db79eb07f689a9b273d3516eee286
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(15882);
 script_version("1.18");
 script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/01");

 script_name(english:"Hydra: rexec");
 script_summary(english:"Brute force rexec authentication with Hydra");
 
 script_set_attribute(attribute:"synopsis", value:
"It may be possible to determine rexec passwords through brute force.");
 script_set_attribute(attribute:"description", value:
"This plugin runs Hydra to find rexec accounts and passwords by brute
force. 

To use this plugin, enter the 'Logins file' and the 'Passwords file'
under the 'Hydra (NASL wrappers options)' advanced settings block.");
 script_set_attribute(attribute:"solution", value:"Change the passwords for the affected accounts.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_attribute(attribute:"cvss_score_source", value:"manual");
 script_set_attribute(attribute:"cvss_score_rationale", value:"No CVE available for this vulnerability.");

 script_set_attribute(attribute:"plugin_publication_date", value:"2004/12/01");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();
 
 script_category(ACT_MIXED_ATTACK);
 script_copyright(english:"This script is Copyright (C) 2004-2023 Tenable Network Security, Inc.");
 script_family(english:"Brute force attacks");

 script_dependencies("hydra_options.nasl", "find_service1.nasl", "rexecd.nasl");
 script_require_keys("Secret/hydra/logins_file", "Secret/hydra/passwords_file", "/tmp/hydra/force_run");
 script_require_ports("Services/rexecd", 512);
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

port = get_service(svc:"rexecd", exit_on_fail:TRUE);        # port = 512?

# TBD: check that the remote server is up & running

timeout = get_kb_item("/tmp/hydra/timeout"); timeout = int(timeout);
tasks = get_kb_item("/tmp/hydra/tasks"); task = int(tasks);

empty = get_kb_item("/tmp/hydra/empty_password");
login_pass = get_kb_item("/tmp/hydra/login_password");
exit_asap = get_kb_item("/tmp/hydra/exit_ASAP");
tr = get_kb_item("Transports/TCP/"+port);

if (get_kb_item("/tmp/hydra/service/rexec")) svc = "rexec";
else if (get_kb_item("Hydra/services")) exit(1, "The installed version of Hydra does not support the 'rexec' service.");
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
} else if (! s)
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
    set_kb_item(name: 'Hydra/rexec/'+port, value: l + '\t' + p);
  }
  else if (line =~ "^(Error: |Sorry, hydra)")
  {
    errors = make_list(errors, line);
  }
}

if (report) security_hole(port:port, extra:'\nHydra discovered the following rexec credentials :\n\n' + report);

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

  exit(1, "One or more errors occurred while running Hydra against the rexec server listening on port "+port+".");
}

if (!report) exit(0, "Hydra did not discover any credentials for the rexec server listening on port "+port+".");
