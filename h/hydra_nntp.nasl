#TRUSTED 8f3235e184c88271d4f1846f1269043e9877a208a3ffad79034351eb16de72a75a3dabee6b03ec3f95813f313f44a37f66eefc30352a2d0b367a1a25a619742accfd8f427a7f3e5976b88c794d17dd5b958a55b69b830ee30e5c5fb2b106604818a2e6862e9feea82b2f6f5c8fb8538a17c5a5728c54b2f680f01c7a2bae3a85f00a809a256e960222db7ba79372a2c687e5c1511a751ed16525d3d1ae8e7025b353f2fd055118157a53ac29dcd77715964b28d4099fe4819bd4f8470e1f6bd790b17c8896487d31e0cf8a0ab09673b57f0e09e8ed2d6a1685a20dae58049873fc258a646be2bc60ac219e0cff78df6c59f0860bcf182b87f7cbc660ea673b5bc98a7025e608aa69ade6f206648b3cd0bf1d3fcc9a1b35a84bddec8dc1255042091a6e62d6a0574b922e0a425bd6134f32828702182918207f18e5d12dbf299f637a53aac7eda64340f1d45890beba55b26d07c2f01610b5c9a29ba7c9227227226d2f382c5eeb3362d8e10e140ea3b4e275db63e7ff67b6992b7bf856beaf5f7f3aecc8fee6fff801d3415a2d640a6608e767e7aef8efe65b0d178dc12c9c3e0cf9336f9e844089644dbf48edf5fe383581f77ec283556b1e62533c89402bf08dc8a33766e3dcd3e6487ac4946da28e31739d760ccbc2587070585158f735a4e3c8f57571e48b3c6be16111505888f38aa519c2eaa3fdcc6c2a1818ceda74ad
#TRUST-RSA-SHA256 35526d4d8c627eee3e83d52b7bd17fe964cf4a209cc7680a0cec59ccf4c7ab54d45c2d3f7ffc0483d140aee42683497df6b3de3514e087e107a288afa6bf8a2d94053d85a075a23520d564864e2150256b334448b64b3b4cfb229e525ebe03acbb4ed9e7692d888a989eb3099540ad15ed9e8a2f72005540c7a4c476db4bfc2e19abe95635c74b0ef03cb59733cb0583b1cf363d1f9b46ebd51ee13e34041d72bd2c1b10d570dbd7031d8dabbf773cb0ca602e443db742d75efdaae9746b943f307010365e483386ba2abcd80513bea4a5ba5649b18319b42ea0c366a88b0a836f365c28e6992c3ebb3433355948626b9d011f5140915293fe0b02f49c412d7f32fd34d786772dbff37d3e40438288bc51ddf2d5c5464781a4faad163d4012af6345d76ba87d304c342cef55db3078e91bea7f7cbbf89971f968f08e3bb73f8dcbec3e9178edf8dadd359b46e767220d131d285d605f93a04b63b5dc0279f9d0793553625d2c9336f242b533ee42cecc9936df8d8faa153c7fcc1cc720061fdd26e237cebd6ebbb66d8545c34bf0c49f4aa1f2f9fead26313bd4bc5158b4eec0d6df29a8415053b11c312e6de8cf6aafe20eae9c2d8a3e16f8841dac9d298b279bda6f07e044820eb25fbdde3558c0eb5d72b128384d6a8c26e64156ff27a7ef5e551e346d66f4bd479695d2492c028ff9a42397d8fdf61d7de7b93e40d2115e
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(15879);
 script_version("1.18");
 script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/01");

 script_name(english:"Hydra: NNTP");
 script_summary(english:"Brute force NNTP authentication with Hydra");
 
 script_set_attribute(attribute:"synopsis", value:
"It may be possible to determine NNTP passwords through brute force.");
 script_set_attribute(attribute:"description", value:
"This plugin runs Hydra to find NNTP accounts and passwords by brute
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

 script_dependencies("hydra_options.nasl", "nntpserver_detect.nasl", "nntp_info.nasl");
 script_require_keys("Secret/hydra/logins_file", "Secret/hydra/passwords_file", "/tmp/hydra/force_run");
 script_require_ports("Services/nntp");
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

port = get_service(svc:"nntp", exit_on_fail:TRUE);

if (get_kb_item("nntp/"+port+"/noauth")) exit(0, "The NNTP server listening on port "+port+" does not require authentication.");

# Check that the NNTP server is up & running
soc = open_sock_tcp(port);
if (!soc) audit(AUDIT_SOCK_FAIL, port);

r = recv_line(socket: soc, length: 1024);
if (r !~ '^2[0-9][0-9] ') exit(0, "The banner from the NNTP server listening on port "+port+" is not 2xx.");

# Double check that authentication is not needed
ng="NoSuchGroup" + string(rand());
send(socket: soc, data: strcat('LIST ACTIVE ', ng, '\r\n'));
buff = recv_line(socket:soc, length:2048);
close(soc);
if ("480 " >< buff) exit(0, "The NNTP server listening on port "+port+" does not require authentication.");

timeout = get_kb_item("/tmp/hydra/timeout"); timeout = int(timeout);
tasks = get_kb_item("/tmp/hydra/tasks"); task = int(tasks);

empty = get_kb_item("/tmp/hydra/empty_password");
login_pass = get_kb_item("/tmp/hydra/login_password");
exit_asap = get_kb_item("/tmp/hydra/exit_ASAP");
tr = get_kb_item("Transports/TCP/"+port);

if (get_kb_item("/tmp/hydra/service/nntp")) svc = "nntp";
else if (get_kb_item("Hydra/services")) exit(1, "The installed version of Hydra does not support the 'nntp' service.");
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
    set_kb_item(name: 'Hydra/nntp/'+port, value: l + '\t' + p);
  }
  else if (line =~ "^(Error: |Sorry, hydra)")
  {
    errors = make_list(errors, line);
  }
}

if (report) security_hole(port:port, extra:'\nHydra discovered the following NNTP credentials :\n\n' + report);

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

  exit(1, "One or more errors occurred while running Hydra against the NNTP server listening on port "+port+".");
}

if (!report) exit(0, "Hydra did not discover any credentials for the NNTP server listening on port "+port+".");
