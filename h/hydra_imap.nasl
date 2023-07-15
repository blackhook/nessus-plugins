#TRUSTED 8b605bd0d624a3b4101453eadcc0874c67643da40d6f8a0192619e63414221629fffe43443118457712f1c84f6d974ef78d4d091a4e9e1e7e5a96a898a1921e160a30b3920c6e532ea6c2e7dcbdfda2e065fb8f13e294a80b8f5cf03de2322a4b0b4012aaa0f1e525be9b2418a5121d26603271626375d0f7b5144d3727277875d44c655dcda5ce71f6decdd3f32dff7bc30210ecddb8cc3839f23394bbd44395257d983cea59c8781575cc0729940d40349f0dc6140aaad81e5227bd8fa6ee377370c7641cb78506e8c9cc5ebe52700f6336d63aa3da9cb1bfa4bb4c7a9c360c165722a3b9d90cee301609e30792c74f85b9d22740f4cf7c71a20edd197108a6c3876c43304c61b4b6344cb942ff8af4ef5282789d2df514a2cdc9ea181b7ba54282ab525e94e9ba8063428cb8344782f2b16d2c0ce079114853da26264028026c068fcb157009cde803c50e7ae488a2c0ff1d8246f6835d8385156672a16fca8326a6c333535f18a400b083bfb46a183d60c76493e1d89817d960058209dc5cc651ad4f40ac1cc276d1d0bdec5697993e6d6c02ad232ea3624cef2841ad018ff031814a22d5bd82961395660c6e7bd72f5032984f60619c7b6202d6d2f9a9ac76882986f344c126dd28be74c84f8043f9f1f4bd2e4b0d9798eaf5d375d6e873618a308cdb0b9add8174d257ebd8f3a57d690a882f8fadf391f1b33573db22a
#TRUST-RSA-SHA256 5bbdb8946a58471ad35c627a43b6af48f4d16cc26612f1a49c8ba3dc74be3758e7296d5d4945b0fb7523617899a1dbca4afbcb4e77eb7f6476939f8db6c35f758df9a537bd64de6ef4edbdc8319d859cbdf7098a2081e087e3e7fc9513629ec4e0c5c2947bca3c4eeddbe961cc6b6f4871b30825e4b3138dba2dfccc9f36655ecf5f828864b25341765cdb879e74fa2b22a722e45677d70cdfd7885303395ed6b16bc035ab36e9fe83b06350c4787b087380665c59819e4ab40a4b929357c6e808993697735c60ff586160467ad471b1d3d409862100b4a67f89f1534b53ae5af20bf4277ae00bfc0cdf310f04fafd9e6faaaf3d3a0452969ea5392e917d54667997a8f70fe29ac027d234415bf662164c0976e8c6d9837dbdf194cb639a78d504e5e989d01abd09ea44e066d6e2dc986e05a326d4e751ae7ed1d3386f43ba2aeef7fdf85605fa9ac1ef9e9152a295a66c075469a64e78e01537f17a14453986e131bd2aa5a4b8f4ebf58c517db5af00f9ca9b3c90a5a87c8fb5657dc7ae5c33d77706bfc7c0f01824b2a70ca176b79b4799a4046d675a7b8ba0920a23dfc91e1fbddd3b90975292532a5ac5f94fd35b3dd0872a222e986f17ba2067ba3ff7a3af8618322caf9f33ce7e5b5a2789c1c83df67f9dd5d6e4a9072e7d51922fde1444be232034c06ddba6ebc7029658a577562eda743417acbd468200fe0f8b0327
#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include("compat.inc");

if (description)
{
 script_id(15876);
 script_version("1.20");
 script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/01");

 script_name(english:"Hydra: IMAP");
 script_summary(english:"Brute force IMAP authentication with Hydra");
 
 script_set_attribute(attribute:"synopsis", value:
"It may be possible to determine IMAP passwords through brute force.");
 script_set_attribute(attribute:"description", value:
"This plugin runs Hydra to find IMAP accounts and passwords by brute
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

 script_dependencies("hydra_options.nasl", "find_service1.nasl", "doublecheck_std_services.nasl");
 script_require_keys("Secret/hydra/logins_file", "Secret/hydra/passwords_file", "/tmp/hydra/force_run");
 script_require_ports("Services/imap");
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

port = get_service(svc:"imap", exit_on_fail:TRUE);          # port = 143?

# Check that the server is up & running
soc = open_sock_tcp(port);
if (!soc) audit(AUDIT_SOCK_FAIL, port);

r = recv(socket: soc, length: 1024);
close(soc);
if (r !~ '^\\* *OK ') exit(1, "The banner from the IMAP server listening on port "+port+" indicates a problem.");

timeout = get_kb_item("/tmp/hydra/timeout"); timeout = int(timeout);
tasks = get_kb_item("/tmp/hydra/tasks"); task = int(tasks);

empty = get_kb_item("/tmp/hydra/empty_password");
login_pass = get_kb_item("/tmp/hydra/login_password");
exit_asap = get_kb_item("/tmp/hydra/exit_ASAP");
tr = get_kb_item("Transports/TCP/"+port);

if (get_kb_item("/tmp/hydra/service/imap")) svc = "imap";
else if (get_kb_item("Hydra/services")) exit(1, "The installed version of Hydra does not support the 'imap' service.");
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
    set_kb_item(name: 'Hydra/imap/'+port, value: l + '\t' + p);
  }
  else if (line =~ "^(Error: |ERROR [0-9]|Sorry, hydra)")
  {
    errors = make_list(errors, line);
  }
}

if (report) security_hole(port:port, extra:'\nHydra discovered the following IMAP credentials :\n\n' + report);

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

  exit(1, "One or more errors occurred while running Hydra against the IMAP server listening on port "+port+".");
}

if (!report) exit(0, "Hydra did not discover any credentials for the IMAP server listening on port "+port+".");
