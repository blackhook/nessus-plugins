#TRUSTED 064a166983d3939733b6f142738b773034767eddb6f0814462f44168a58a1e6fdd58d2e02ee7197c4ebf92c1656ede529ca68c5821deb974fd695bcc1c7db5303429d5fbf9ed79c6e3b06b1704363516780b471436aff7892fbaef54d93ab18d15a1b10bfab7246e8ca97432e87944756379a7503904e0335a3a23b8bce9ad1bccf5369650c9f74c37667094fcec014e39787e98d7923a915df9db23c7c139d34c7a319a2408c686dfcd540ea7650a72c09afa9a45b179e7be00aa6b75e2b5dd72e57d5db564350c2298234b9afd0ee60feae5a85f9c9c5ad059eb849123a8fea5b0ca60236f5e595628952325b941022d4468c5e21da0d0151b68f39d364eb8b577fcdc7eb68f95d01b65938a6d9f6ff1825386943576c7e5842e3f7f696ee8c09e5519db4d80a9200ae878e912050ce5be35497d646bd0305e42647f590927effdb16ba121c0984b6db22f53d7f97e3925a563c8008f6992e3ad5be7f926d8b5535c592a786b9f80896a3ee3b2e6f11a4273e537f01cd816472f5eac28ee1afc1a0f674ab37e23c43c3600fd47ffde0b12a6388cbdad415e7bb20d47e901b378fb78b74dae2b23c5122680d4f466ce4572a32dc67313f9db03fde6648064c1d1d5eab1315127fab4407b9eb1b380064ce9aa7de7424b91a8404beb8f0cf878d36642566745e4efedf465f5f509ea3e3433a282a7b261bda47b633666af025a
#TRUST-RSA-SHA256 9c8e2f52779000e63acabb6b9c5c1a3a2ecfa7232e558530ac3777ac7f36131594af3059c91a5307303c147973846aeb45dd5149baae1fcad2ed58fb088403276ef5838bf3aeff1993ca53fa7cd62ee89d70ed44076f9ff3e72e4427e2fb1bad2617d6ced87b1117a1ed12aabda56d883c78ebecd6456bb015247e8a760a01d93a4abf55ccba922d6d61cf20d08550048650f7fc0781c9e026cc31cc62b264e9903fac03d559a284867d3268a5b52bff8c9f38271682d3d10895165b3d5cffe3bc4449f18a05c69fcc2b5a15be69d4bfeed47f359f3139259193f4da36cf8b5a49939df4271cc14cea5034d6d557c5027eb0b65368c08ece649fc0cf7f7f8eb5d8b735886628b786c0a31ace0f69bc65753bf0e0169d9cde8e9e3c10218d4b868a4fbc31664ac96ae49954e6881d6a6f089ac9dced331e176c3dc5bd9af708b98dd74efbf242c0f9eca0b3ef9cdc14e85f3436f7607e380284b341af09d45f98697fcf3dc5b66e669b8b5a2cbe5c213953af2f4967aa34ddd32bd7f836bde4bc57f6194c808b95ebb47ac8acd33d78235ef91f479601ce310cb2272bfcb6a6da1f4401eaba1c616da6e0e5eabf7d54de505793634bca7dc311e98789e3e53a1e9ef603f79830763e7dabca23e780225f8a8c4f9ab2b7366803a263557e0d7d094ebbc763a8ca9449109cd526fb3fe5f704a61463a6ce22dfecc68b0e228b9a87
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(15871);
 script_version("1.18");
 script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/01");

 script_name(english:"Hydra: CVS");
 script_summary(english:"Brute force CVS authentication with Hydra");
 
 script_set_attribute(attribute:"synopsis", value:
"It may be possible to determine CVS passwords through brute force.");
 script_set_attribute(attribute:"description", value:
"This plugin runs Hydra to find CVS accounts and passwords by brute
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

 script_dependencies("hydra_options.nasl", "find_service1.nasl", "cvs_detect.nasl");
 script_require_keys("Secret/hydra/logins_file", "Secret/hydra/passwords_file", "/tmp/hydra/force_run");
 script_require_ports("Services/cvspserver", 2401);
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

port = get_service(svc:"cvspserver", exit_on_fail:TRUE);       # port = 2401?

# We should check that the server is up & running

timeout = get_kb_item("/tmp/hydra/timeout"); timeout = int(timeout);
tasks = get_kb_item("/tmp/hydra/tasks"); task = int(tasks);

empty = get_kb_item("/tmp/hydra/empty_password");
login_pass = get_kb_item("/tmp/hydra/login_password");
exit_asap = get_kb_item("/tmp/hydra/exit_ASAP");
tr = get_kb_item("Transports/TCP/"+port);

if (get_kb_item("/tmp/hydra/service/cvs")) svc = "cvs";
else if (get_kb_item("Hydra/services")) exit(1, "The installed version of Hydra does not support the 'cvs' service.");
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
 exit(0, "No Hydra password file");

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
    set_kb_item(name: 'Hydra/cvs/'+port, value: l + '\t' + p);
  }
  else if (line =~ "^(Error: |Sorry, hydra)")
  {
    errors = make_list(errors, line);
  }
}

if (report) security_hole(port:port, extra:'\nHydra discovered the following CVS credentials :\n\n' + report);

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

  exit(1, "One or more errors occurred while running Hydra against the CVS service listening on port "+port+".");
}

if (!report) exit(0, "Hydra did not discover any credentials for the CVS service listening on port "+port+".");
