#TRUSTED 1434496b05f46432fab8a25f501a09bb910547e7c4a47f71b519046592406fd5e06373d5c39ca17788bb2f56ab282e98581fc82eb99174887521cc4b9dd3676fe96fb39238d609ae169ba36e8e862f85da4a12140b54c8c5994fe71fd8da6b95531d6d036ce94615ed3d778517b57aaa33c47ddf8b1a3089092e8af3e630367101d3e91eb9e9e6ea96274f4a5a0e4876687cf7c709de2db367b98420169a24be8710de624314835d8a13d25bb7af6f37e2e51fdb8b7841c732201d4afec42155e8602142288ab8bd8c3cf18518b312ade3b1399c7fab3f26d891cbd2d99014a4f25c7db77d6452ea97042633b3e7cf1e3e1b28bac48f5f5f484c5f1cf41ce5cb5c5e4c74a5b29f51641cca8e9e083bb8933d2ad471a88daea507685157021e4c4ef9ac837884cc6037dc1d2d164a013ac078e55840aac22cc9f4b63889efa6611fc87faea1f6746638ef59af57b865d139ecd494a46c992d2ea297d09883d2bda4083c2847e6de86440a58dd3fcbf5b9a9acd90dd366ca5da84c8eb6d5cecc7c14be153e4158d8b02700bd1b983230104004d0e72adb736507a2fc399c19f1317f712f1e1c46b79fbe01881ff8c2309806617826f361676674a587ff71e3f5a264cab8dc1aea6faac13ff91b933c39313fad3f01db50ae20b8f2a9e0819ca57ea16d31359858065b79a1182d529c02f9f7060e0a56a0c47285c80bfdee16077f
#TRUST-RSA-SHA256 565b18d1539b730e1a53a150b447888e5527886fe0fc647056a879920b7ae586d06f53cd8a1a253c8fb31ff5b795dfcf12edd05fd5e860902564d20779434122a4c2ae0cdb5ba643ed9b43361a2531d1e35ad5cf75cd320820892506cffd1d754ac6045f9cee1675dfb4702d8b48a99fd1930ad3b4b2ba5c0b208dc52708333fd65f4b86874fca0096f8d6d9de1c0fc24dc9d80d47b2bf6958de2b681d64d762922ff0b14f5211b574d700051a06d78c5a3e8e66f7082cac5b53ee0ba956921e48d59d20563f7b953b389c0fc6c4e570bf598a690a6107cf53a1154e267c7ab548a9d70966f7692c5b354c9ebcd9d2dc2729cb4eef5b3256d8ac00ccf76efd7ad8abf60864b446636ed7cd4cb7df6d82ff5d3e9c34cc147765bb0a5b662c896e849727516f2cd6e954ed284362903202c9e99ed628d20ad3d13fd66c6b3c0c8dc74967e1be1a5b15fc4a4315b6cf97f63efd8d05d477151219aec38feb7cce400c2347016703d13f3ae8e600d7cda3a4adcfcceb99cb79b6e4b27c6073e5d6a83afb7c6aafe3d6de4f019272efa0cf863610ab8584f87fd28fdd7f1ee5b11e0be7214f4be66cdbcf87bb8a063ca89e50b0ca808e44f21d355568c8b238207978706106260e347eb9a1c4e9d14507742d66383d0276b211dbec22069bdbae127280214bc4dd7871abfea71d42030ee7e2996a6e7b739e5460589c8b8569f2743b
#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include("compat.inc");

if (description)
{
 script_id(15880);
 script_version("1.20");
 script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/01");

 script_name(english:"Hydra: PC-NFS");
 script_summary(english:"Brute force PC-NFS authentication with Hydra");
 
 script_set_attribute(attribute:"synopsis", value:
"It may be possible to determine PC-NFS passwords through brute force.");
 script_set_attribute(attribute:"description", value:
"This plugin runs Hydra to find PC-NFS accounts and passwords by brute
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

 script_dependencies("hydra_options.nasl", "external_svc_ident.nasl");
 script_require_keys("Secret/hydra/logins_file", "Secret/hydra/passwords_file", "/tmp/hydra/force_run");
 script_require_udp_ports(640);
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

port = get_service(svc:'pcnfs', ipproto:"udp", exit_on_fail:TRUE);      # port = 640?

timeout = get_kb_item("/tmp/hydra/timeout"); timeout = int(timeout);
tasks = get_kb_item("/tmp/hydra/tasks"); task = int(tasks);

empty = get_kb_item("/tmp/hydra/empty_password");
login_pass = get_kb_item("/tmp/hydra/login_password");
exit_asap = get_kb_item("/tmp/hydra/exit_ASAP");

if (get_kb_item("/tmp/hydra/service/pcnfs")) svc = "pcnfs";
else if (get_kb_item("Hydra/services")) exit(1, "The installed version of Hydra does not support the 'pcnfs' service.");
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
  v = pregmatch(string: line, pattern: "host:.*login: *(.*)? password: *(.*)$");
  if (! isnull(v))
  {
    l = chomp(v[1]);
    p = chomp(v[2]);
    report = strcat(report, 'login: ', l, '\tpassword: ', p, '\n');
    set_kb_item(name: 'Hydra/pcnfs/'+port, value: l + '\t' + p);
  }
  else if (line =~ "^(Error: |Sorry, hydra)")
  {
    errors = make_list(errors, line);
  }
}

if (report) security_hole(port:port, proto:"udp", extra:'\nHydra discovered the following PC-NFS credentials :\n\n' + report);

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

  exit(1, "One or more errors occurred while running Hydra against the PC-NFS server listening on UDP port "+port+".");
}

if (!report) exit(0, "Hydra did not discover any credentials for the PC-NFS server listening on UDP port "+port+".");
