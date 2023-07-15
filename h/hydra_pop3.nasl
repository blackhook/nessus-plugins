#TRUSTED 24e55efced4f96a007acaeb86d951e07aa6c1bde44cd311e87ff1c18c2793eb0fab352df2ac789d67265e8d092b3de051e01fbe5282c0de67d0d9a5fdfd0f2ff6ff44eec08c8d85f30325a2d6287b35aa04a542acc0bb2ed5a6164020f511be2fdfb5013922404e2c2ac410bfa48c29c29ad536e732cc1325c2d0a62f74aa3b0c3a777cb7a2b65013c5ee850d37d509886d93d1a3bdf45cf02a9c50239b42a310da69c84a20172adaf282d5361a04d18134f25c6eae983f1b3485315c0b53962a921f86a7b73c23285f09294023adfb1b30e89b3ba3d1d2f7e4bf8780377f23bfc2e12b0f1de74fb9832e019fdc1588c734288911b11112ef6372d9264277716b35ddf7cb0a19810abeeaae7bb886d0e64120a55dd9da5665dec668bf967f482d4ff1dc4162efccfc54ccbf004445b1a2301901f5a2d05b8e7652b5deaaf2641f3dd7d99b9c180d1e3b0622c9e89d41d9e22f7fe96829e0ee6b6c3429bdcf6e9e6684ca211583d1b18eb0bbd1395e8aee19e035bbcc6568b0e2391162ed59bb76c7dba7a3ce463b00d3b36c3f87b24d0fd9a2725093aa49bb1f42efb1378a2a16f0659bb07b426f4e2a8c12622e1b307643d900035924dead2fc1a646c4f4114818a4f00fc5ae82e717ec47c3d027e18d81569baa23b857cc51367d08eb75195d048ec7676be4df3c0123158e0c562f329021881578367fae12e2d5e834211cc
#TRUST-RSA-SHA256 1a6fbf9d80cc903ca6b06f525ad7a7d4b98a05fda4cb8ee3ceb351e54c68e9da25c5a019c96bfaf2ab54582ad43cffd9bf50c7354fc60b65dfea6d56641f9343ea8e12b2c54b70e51cab0855bb8407bbaee403db014809369678b972acea08796be2807de7ca32f5a4a5c7761c163f7c609d2baf3504ed2ea3e021f4ee0d6ebcc473b29334ca1af19e0da419368e4d30394dc357d99e7668528720fbb2fc372149680dee774ec68a8a0d812a8a734577caeb04185e2fa234ade449ca4ad0f6a1110558d66763d5cb9e22e81b76e8909e0160af188dbeee3389f214e5704e55f5d62f1c725cbdb15b52893a81b9d8a927f86a2999996a008306d01d0a5ea7d71bd6be38dd7f6c68d9c6ebcbefc3eed5cdd828aec400d6b873763e153193a947c699580f41480097e9ecd6f71966fd81072791df427d7e25e553ac3afb6c7c20646e963b24ba825f754ed9889a5896ebc1fdc5e189c84598458426983319d73dafac2ce22c370aba1d11a41f5a3710692f25aee0ba07c36f731b9b4ad9c432bddde683648613ac1a179eda42a8340df0f24cc8ec429dc002807cbe7ba401c85b06aeac6db9fa2ba9f85b8c20def3dbd4631952d9856f47cadb4333ad1ca72249848402ee4f658aaece2ff9d47e4cbd66d214781b18a2318e155d7f6923de9f97cb102baea0cb665e6102ad21dcb231d60ca2fa48272c8b35f3c331c42fd64abcf2
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(15881);
 script_version("1.19");
 script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/01");

 script_name(english:"Hydra: POP3");
 script_summary(english:"Brute force POP3 authentication with Hydra");
 
 script_set_attribute(attribute:"synopsis", value:
"It may be possible to determine POP3 passwords through brute force.");
 script_set_attribute(attribute:"description", value:
"This plugin runs Hydra to find POP3 accounts and passwords by brute
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

 script_dependencies("hydra_options.nasl", "find_service1.nasl", "doublecheck_std_services.nasl");
 script_require_keys("Secret/hydra/logins_file", "Secret/hydra/passwords_file", "/tmp/hydra/force_run");
 script_require_ports("Services/pop3", 110);
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

port = get_service(svc:"pop3", exit_on_fail:TRUE);       # port = 110?

# Check that the POP server is up & running
soc = open_sock_tcp(port);
if (!soc) audit(AUDIT_SOCK_FAIL, port);

line = recv_line(socket: soc, length: 4096);
close(soc);
if (line !~ "^\+OK ") exit(1, "The banner from the POP3 server listening on port "+port+" indicates a problem.");

timeout = get_kb_item("/tmp/hydra/timeout"); timeout = int(timeout);
tasks = get_kb_item("/tmp/hydra/tasks"); task = int(tasks);

empty = get_kb_item("/tmp/hydra/empty_password");
login_pass = get_kb_item("/tmp/hydra/login_password");
exit_asap = get_kb_item("/tmp/hydra/exit_ASAP");
tr = get_kb_item("Transports/TCP/"+port);

if (get_kb_item("/tmp/hydra/service/pop3")) svc = "pop3";
else if (get_kb_item("Hydra/services")) exit(1, "The installed version of Hydra does not support the 'pop3' service.");
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
    report = strcat(report, 'username: ', l, '\tpassword: ', p, '\n');
    set_kb_item(name: 'Hydra/pop3/'+port, value: l + '\t' + p);
  }
  else if (line =~ "^(Error: |Sorry, hydra)")
  {
    errors = make_list(errors, line);
  }
}

if (report) security_hole(port:port, extra:'\nHydra discovered the following POP3 credentials :\n\n' + report);

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

  exit(1, "One or more errors occurred while running Hydra against the POP3 server listening on port "+port+".");
}

if (!report) exit(0, "Hydra did not discover any credentials for the POP3 server listening on port "+port+".");
