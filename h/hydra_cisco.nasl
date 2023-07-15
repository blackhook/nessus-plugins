#TRUSTED 037819c077f9fd658bb894f2d2b3a2ccaa2521a68d3d55d101ce2a2f5c7243830005ac7ae8ce05432428d90bc59a8fd0ead8bdbd3ad86a60a1c8e2d89f891281164c651a5c752d8e3cbcbb7eb7c81b8518cd45051c691cc894dd38a96fb3726993e61a071f3fd2c9ce128283d2c2477ee25c4c024906b4153020a041ed83c2d807852b8f34094ff79304b003bf73dc1e8547321959645a463648a42e056b7919a256ff63523bf26cfc344bd62ab5c3c6d87564ac98b1ba72b8df8f0dce85e21e0bac16308fd9d64b2351d0deac2bc32895d8bcb25c4ea62fe61eddbea589b35c77826942f16a29e7aa25542f25b0b4dc637d00038fa6739263387edd9e797fe48d28cd7843806d5527149a70eea8ce6170165a4482612acdd3d54e18dca928d97b16eb29435e237f3611548049fc56177c94f02b1395a3953ca4e86689eabbed3a3ca93e10a16e225f0bb93f800f7dbf476c31c726c351005e5230ac9d501fa87b5abe2db996a1cfa2cadde509c0b8e37b13eb5ef52b2bb67991d0dad15984b4728527005d9c1afdf1aadf122ea95044f4864276a9b4d582f71237b7f5325da1684c2f9168f47701b54979bfb3640e076009b895291677374dd454b4756d82212448f28146d10740cb5c4d0ceb7981a761ac8d4bcb06ddaf9d6d944814cc14c45fca58e0680309a100c9c1b4b1c4e05b9cc4f430b31f771641d123806cfe41ed
#TRUST-RSA-SHA256 066b696e2c85d235024d0aaa6b0d3bf0898bffe0325ec66b64cb2f71ce7aa650fd12c88c668dcad424188bc462a13c6b8e53761499522770157045ce43300e6274e32d60aed46dbba32a1b1685cbdb0776a8d49ec72fcd661d2a635bc8539d99ea17d84d96716aafa815f8ba222ca8a7c8b5da6054d6bf80e4121006a5709c1fd32e932c9a6518a2f53290a26f5eed5c4108900aaa90d801dac9278fd3248fd0f2dd45ad48be79dd642ee1651dbe7c2c3f1dcca1e973ce853db64bba15bc2564230007c2b3096273cfceb5fc91b8d40a675dde2088eaf0a32a1a3de2b3e156e8f62c11ebeaef412512b491c15311b45bbe0d4842900b277e255844480e35f7732d02dafc63a167c0a6cc7be779a000e55ce4509ef0f81f598b57358ddf94db512b2004abcc0b6bedd2a73659c5ca52c0bcc7b720ff3414a96d523a12d26f6c6c8b88b4097af77bb72672022dc6923e92081e593672e8ef067a6d97f44f199d99980d03575b0394f8630d5678baa8ca8189724d5a8bc008b2f1eaa131ae440065baf451a50e1fab0edf9899e0427e72c9bdd0f03eb1dbc1ca0cbe697cd008fe4eac350b438c9cb4287c75ce55800547cef9bb1e7fd80d88785f9030ef31a7445f11d92a4bf792b492f234bed77b57f40bbecf4d6592b6b600bef0fb0a9b7b31f96104dcd804fff40995231d3df02186526c65ae6c08339e8c2f638335bbb30886
#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include("compat.inc");

if (description)
{
 script_id(15869);
 script_version("1.18");
 script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/01");

 script_name(english:"Hydra: Cisco");
 script_summary(english:"Brute force Cisco authentication with Hydra");
 
 script_set_attribute(attribute:"synopsis", value:
"It may be possible to determine Cisco passwords through brute force.");
 script_set_attribute(attribute:"description", value:
"This plugin runs Hydra to find Cisco passwords by brute force. 

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

 script_dependencies("hydra_options.nasl", "find_service1.nasl", "doublecheck_std_services.nasl");
 script_require_keys("Secret/hydra/passwords_file", "/tmp/hydra/force_run");
 script_require_ports("Services/telnet", 23);
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

port = get_service(svc:"telnet", exit_on_fail:TRUE);       # port = 23?

# Check that this is a router
soc = open_sock_tcp(port);
if (!soc) audit(AUDIT_SOCK_FAIL, port);

r = recv(socket: soc, length: 1024);
close(soc);
if ("Password:" >!< r) exit(0, "The banner from the Telnet server listening on port "+port+" does not have a password prompt.");

timeout = get_kb_item("/tmp/hydra/timeout"); timeout = int(timeout);
tasks = get_kb_item("/tmp/hydra/tasks"); task = int(tasks);

empty = get_kb_item("/tmp/hydra/empty_password");
exit_asap = get_kb_item("/tmp/hydra/exit_ASAP");
tr = get_kb_item("Transports/TCP/"+port);

if (get_kb_item("/tmp/hydra/service/cisco")) svc = "cisco";
else if (get_kb_item("Hydra/services")) exit(1, "The installed version of Hydra does not support the 'cisco' service.");
else exit(1, "Failed to get the list of services that the installed version of Hydra supports.");

i = 0;
argv[i++] = "hydra";
argv[i++] = "-s"; argv[i++] = port;
if (empty)
{
  argv[i++] = "-e"; argv[i++] = "n";
}
passwd = get_kb_item("Secret/hydra/passwords_file");
if (passwd)
{
 argv[i++] = "-P"; argv[i++] = passwd;
} else if (! empty)
 exit(0, "No Hydra password file.");

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
  v = pregmatch(string: line, pattern: "host:.*(login: *.*)? password: *(.*)$");
  if (! isnull(v))
  {
    # l = chomp(v[1]);
    p = chomp(v[2]);
    report = strcat(report, p, '\n');
    set_kb_item(name: 'Hydra/cisco/'+port, value: p);
  }
  else if (line =~ "^(Error: |Sorry, hydra)")
  {
    errors = make_list(errors, line);
  }
}

if (report) security_hole(port:port, extra:'\nHydra discovered the following Cisco passwords :\n\n' + report);

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

  exit(1, "One or more errors occurred while running Hydra against the Cisco telnet server listening on port "+port+".");
}

if (!report) exit(0, "Hydra did not discover any credentials for the Cisco telnet server listening on port "+port+".");
