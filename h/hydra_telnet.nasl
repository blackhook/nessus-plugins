#TRUSTED 63901a1eddeb8159c23cc2d433789646d0e7f31acfced613f98aeb3fe108d816480357aa975ca43168a2c266fccd8fc8f49efbc7976f6daa11ab09a096bb631148c3937b54da177b2f089ceb22642068695a42335dab9e8476230e5e16aa5565630f2b8009f9d09758c52deb8676bef499e7e5943374b68fd8f72d6c75bc9c25e2226dba5f8935d1044dc28fac3b35b36062ca151c983ab881e60a1a0857214da63224dd49e02eec65086cbfdb6306e039e8386998e432de6d6e44c6c724a1aca1d2c51c09ecf84d9442834eb94da6721691585a3ac6511de0c54e0be123180d06d81ed4dd543dba1265f474394122872e26b22445a222807775425ea5dd165f727b44cbee94e9e4af15ed08ef97577bbd3bd7de9cf8da0e60333ada65faa02fbb9010db820ce9ce7eb6c7bd930bf16c7c883aed49bfc34c01f13fd19367c2fe89750c6f9ffbea66dbdc23ba5fccccd74e0a0e070a2df2369cdcf099e67d9aa268fac1a109c62062d940e50376cf759e6890fb064f817af03f3638922fe7d595c35747363f78fc2013ce6aa1e71f515a709e23ae8eb2dc6300b41948d96e0abede9c83e0ace391cceee64c5afc9ef223c4f23674cfa41dd350b193c5a434740960eb8c92ec4d60f001de05fe484d85a2113332ca9e6042aca354891bd604670085e0c88fb3b9666a1394c2485c15bb6529d9efd5f4534d23cf0cb2d5dd883963
#TRUST-RSA-SHA256 5396723bf1b4f91c57323d4dad19479490103bd6259ae333f252fbf517a227196eb3607c87cdf3fe8a5362cf4ef62ad6cf0d10172ca2db21e18d12d0445eb699a1fb117533ad8b4b56f09dff68bcd3bf94052882fc0e02d9241530b0978a42c397bdb96977d3d55e7863e8a695303571e07ad43a79ae1a313e367310274fc13859cb9afaee481e69f945013504364e0c4e356e83e1d7d4fc653d4376a2423b73b5511d730ea16b999cf308cf4702eb2ee1e2868abe5069942f540cea1bdbb24e3db166fe90c00dad7edd9df47890fa0c8712d013470b1d591e9b8926deeebe8b61fcc19cfac730f01c168c9915bc6ea25ff849842039b11a7b1448c8faa2b0f6a24a69fdbbeb0293d57213423f1204089b42b0cbd4d108a7d4bf41e63c62fe6df701a8f05431d77d4d63d951eac79e995bfe0a37d0b12de1540dc3ef7919774697e41a06bc9e39da900182e81e6243551840344c08fa485197dd54352c2b7e8a8ae256194ca3fd3069ecb6297c6306ece0f95a4c7be9bb1dd2a1c8b3769a6cf9d0fea9dd5a7c7b731be4afac14b45efdcaae27c9ef754d237c1769d7d224e7388e9ac5cc20f5ac037d0d546ba6e0758c3ced42fdcf6b1f78b334b7462c2c782918ab5d3b60b4d68430a045ba3b2fd29ff7d337739da3e598416d63d3e6c040e7a79b11c6aacf2282daf4fdecb5e1c903be592a54fbb687153e105271f3687520
#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include("compat.inc");

if (description)
{
 script_id(15889);
 script_version("1.20");
 script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/01");

 script_name(english:"Hydra: telnet");
 script_summary(english:"Brute force telnet authentication with Hydra");
 
 script_set_attribute(attribute:"synopsis", value:
"It may be possible to determine telnet passwords through brute
force.");
 script_set_attribute(attribute:"description", value:
"This plugin runs Hydra to find telnet passwords by brute force. 

To use this plugin, enter the 'Logins file' and the 'Passwords file'
under the 'Hydra (NASL wrappers options)' advanced settings block.");
 script_set_attribute(attribute:"solution", value:"Change the passwords for the affected accounts.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_set_attribute(attribute:"cvss_score_source", value:"manual");
 script_set_attribute(attribute:"cvss_score_rationale", value:"No CVE available for this vulnerability.");

 script_set_attribute(attribute:"plugin_publication_date", value:"2004/12/01");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_set_attribute(attribute:"thorough_tests", value:"true");
 script_end_attributes();
 
 script_category(ACT_MIXED_ATTACK);
 script_copyright(english:"This script is Copyright (C) 2004-2023 Tenable Network Security, Inc.");
 script_family(english:"Brute force attacks");

 script_dependencies("hydra_options.nasl", "doublecheck_std_services.nasl", "telnetserver_detect_type_nd_version.nasl");
 script_require_keys("Secret/hydra/logins_file", "Secret/hydra/passwords_file", "/tmp/hydra/force_run");
 script_require_ports("Services/telnet");
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

port = get_service(svc:"telnet", exit_on_fail:TRUE);        # port = 23?

# Check that this is not a router
soc = open_sock_tcp(port);
if (!soc) audit(AUDIT_SOCK_FAIL, port);

r = recv(socket: soc, length: 1024);
close(soc);
if ("Password:" >< r) exit(1, "The banner from the server listening on port "+port+" looks like a router.");	# Probably a CISCO

timeout = get_kb_item("/tmp/hydra/timeout"); timeout = int(timeout);
tasks = get_kb_item("/tmp/hydra/tasks"); task = int(tasks);

empty = get_kb_item("/tmp/hydra/empty_password");
login_pass = get_kb_item("/tmp/hydra/login_password");
exit_asap = get_kb_item("/tmp/hydra/exit_ASAP");
tr = get_kb_item("Transports/TCP/"+port);

if (get_kb_item("/tmp/hydra/service/telnet")) svc = "telnet";
else if (get_kb_item("Hydra/services")) exit(1, "The installed version of Hydra does not support the 'telnet' service.");
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
if (passwd != NULL)
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
    set_kb_item(name: 'Hydra/telnet/'+port, value: l + '\t' + p);
  }
  else if (line =~ "^(Error: |Sorry, hydra)")
  {
    errors = make_list(errors, line);
  }
}

if (report) security_hole(port:port, extra:'\nHydra discovered the following Telnet credentials :\n\n' + report);

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

  exit(1, "One or more errors occurred while running Hydra against the Telnet server listening on port "+port+".");
}

if (!report) exit(0, "Hydra did not discover any credentials for the Telnet server listening on port "+port+".");
