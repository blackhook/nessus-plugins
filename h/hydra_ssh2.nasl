#TRUSTED 464c7ae84e745c9ba3361ac5b294c09df83714d158156b83d078ae6f2e63620a3ba543e655dd56f3aed40f2a790897749b89158178c917425e1d257d4eab62fbda2dfa7a050f0cdad11e30870f7b21a4cdd6fd3ad4ace939a9022f3f75e319f13e873160b4227e90f399c49f15170596e76bef2cfe85231ccca0853cedb7662acdfef198a47bc18a7f91019c27009452420d6a875839302b5368a41f21e684c0b3f3e875f6101e859df490f03efbff349487f1c3d8696da07e039876065cba0afdefa4855c44e9c6d8697a825c7808a29f56d5d8790d7a96f91b137c20e57a0e26947666d5a3798a3d776d31a14abb810201dbec2b3f68cc5b262295264569ed1c8e4e388bc345b50b7e505ebc2a29782f3b06876bc5438aeb225b148bfe6cff31b00f522bdcec542437c092c7f771e687a836a9ad3a91301564fe980bbb351be654ec0cf9a92f763dd4ab81277a309bf6eb70c8c3eacc761036651cd66bd21f032f61025eac176163331ee5f626d254ce1fe0b98a5288e4939fac16569aa07ea864fa3b24f3f3730b9da4a5491512104c7bceb064f0c2ac1695563df00f157dd0f6fed9cf2ee66ddaf582d516219ddb3ce34f2899cd6b1cb8dee8cf62bad713870b8c5f9340c41ac0858ec7629319c512bb0fca245cd422536671f246ec1d286bad25eb3a47d43d8bca6961653ca35393be31d7d48c78bd9fd416ad064acfbb
#TRUST-RSA-SHA256 6d94d987b08433d082470850aa9e2adb7190547dea53100e92245e58f7fac2030d6491a06739817df5266a871797a0f6b676bb59c5a3b45909c3e2972426bd83dec11e7982638714f68e13ebdefd98d22108090d770965e183a166dac65920972c10f310d4a1703bfc114a45b48e174667de47c921e34cd6ebe2c0c8cf8ef9dbbf2acdbda8bf1f991d7e50317fbfd71408f0f0969eacf9878ed46103634e9c1bbc9cd49440e07f75cde323c3219fb7ea713adbd2252a6e1845e7437d1ba444a53ce163a7f5a48092463405ad57975bb7b0c8e3e443043f5f40e00b088b3bbee6ea7b1907e50d474ed538d6efcc8149557b97a05b25647daaead78bc44588915087dfa3fe7d510bc761d8f05cd720684fcfc21036b28cfdd7fb67781aba232f39454dd86821694dc78850cff4b119d5031c15220bd2a1c7e109a6d508c7e62345903166c473304bfb53f7cebdac72fb4004c11f0d29de108c1c946c83e2bd20002cfbef856374a355ad321f5b2c944b574f96fd71296eaf0155ea256cd006ed4ce0db1f8df7da18cdc5ad9a32d69402f32b5b1905cba10083d8b13d8c01859c57cfee5a6563453ef9cd0e71fe0512fd64993cf02d8a325b418343145e80fe4fc4cf5d9e72fc3367ff3b777c05b5af8d932f343f13eb24ec8a208e9235a0d262071fc9c840d728f4b2894b7392e3e97927a9f627b8c3b0507b0b3ef60e052cf4e5
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if(description)
{
 script_id(15888);
 script_version("1.18");
 script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/01");

 script_name(english:"Hydra: SSH2");
 script_summary(english:"Brute force SSH2 authentication with Hydra");
 
 script_set_attribute(attribute:"synopsis", value:
"It may be possible to determine SSH passwords through brute force.");
 script_set_attribute(attribute:"description", value:
"This plugin runs Hydra to find SSH2 accounts and passwords by brute
force. 

To use this plugin, enter the 'Logins file' and the 'Passwords file'
under the 'Hydra (NASL wrappers options)' advanced settings block.");
 script_set_attribute(attribute:"solution", value:"Change the passwords for the affected accounts.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_set_attribute(attribute:"cvss_score_source", value:"manual");
 script_set_attribute(attribute:"cvss_score_rationale", value:"No CVE available for this vulnerability.");

 script_set_attribute(attribute:"plugin_publication_date", value:"2004/12/01");

 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();
 
 script_category(ACT_MIXED_ATTACK);
 script_copyright(english:"This script is Copyright (C) 2004-2023 Tenable Network Security, Inc.");
 script_family(english:"Brute force attacks");

 script_dependencies("hydra_options.nasl", "doublecheck_std_services.nasl", "ssh_detect.nasl");
 script_require_keys("Secret/hydra/logins_file", "Secret/hydra/passwords_file", "/tmp/hydra/force_run");
 script_require_ports("Services/ssh");
 script_timeout(30*60);

 exit(0);
}

if (! defined_func("script_get_preference_file_location")) exit(0);
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

port = get_service(svc:"ssh", exit_on_fail:TRUE);       # port = 22?

# Check that the server is up & running
soc = open_sock_tcp(port);
if (!soc) audit(AUDIT_SOCK_FAIL, port);

r = recv_line(socket: soc, length: 1024);
close(soc);
if (r !~ '^SSH-') exit(1, "The banner from the service listening on port "+port+" does not look like an SSH server.");

timeout = get_kb_item("/tmp/hydra/timeout"); timeout = int(timeout);
tasks = get_kb_item("/tmp/hydra/tasks"); task = int(tasks);

empty = get_kb_item("/tmp/hydra/empty_password");
login_pass = get_kb_item("/tmp/hydra/login_password");
exit_asap = get_kb_item("/tmp/hydra/exit_ASAP");
tr = get_kb_item("Transports/TCP/"+port);

if (get_kb_item("/tmp/hydra/service/ssh")) svc = "ssh";
else if (get_kb_item("/tmp/hydra/service/ssh2")) svc = "ssh2";
else if (get_kb_item("Hydra/services")) exit(1, "The installed version of Hydra does not support the 'ssh' or 'ssh2' services.");
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

set_kb_item(name: "Hydra/ssh/"+port+"/cmd_line", value: join(argv));

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
    set_kb_item(name: 'Hydra/ssh/'+port, value: l + '\t' + p);
  }
  else if (line =~ "^(Error: |Sorry, hydra)")
  {
    errors = make_list(errors, line);
  }
}

if (report) security_hole(port: port, extra:'\nHydra discovered the following SSH credentials :\n\n' + report);

if (max_index(errors) > 0)
{
  msg = '';
  n = 0;
  foreach var error (list_uniq(errors))
  {
    n++;
    if (n < 20) msg = strcat(msg, error, '\n');
  }

  set_kb_item(name:"Hydra/errors/ssh/"+port, value:n);
  set_kb_item(name:"Hydra/error_msg/ssh/"+port, value:msg);

  exit(1, "One or more errors occurred while running Hydra against the SSH server listening on port "+port+".");
}

if (!report) exit(0, "Hydra did not discover any credentials for the SSH server listening on port "+port+".");
