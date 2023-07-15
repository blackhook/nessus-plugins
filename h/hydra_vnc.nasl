#TRUSTED 142ac6a3803261eb58a894ed2f0ae5f2c2e83be2b30e8aa26791f4cf48856b91a4dc5780572696382037c38cc8b26360cea7492405833a91914b9065605c981649d43f23d9277e0bfc598bc25d345b896aad2e641b190766c507dd271627e956bf473f1f78e739ec0f8f2cbe243f6d35b473411336307ca62fa7254f57f0573c203e302653e58693164b971d1fbb73856b941110ba92d267e835160b271226123fdf02df841ea7fee0ff45d27fbf8d329da91308e76e417f9055494611dde00e01fcfdb51990754221539d1a47077fdfceea6b5c2d5b4b0a8a81f7fc94b6053fd67fd2f3504bdc57b7214a947b9f768b3f4eaba1178fe069fb1663a1649c019bd544ddc0cc80c77963fedbe02a4bda7073fecaa2705817f75bec97a5bd0ecbfc421046e8468c084018426aea7378c03a8bb042372faff4f2feddc4ea6680d764e88e985643608ca357bee9d209ccbbbf84f5a00f40563001182b639bca1254a1f3d2c55b3b4275bbf3121728e11d96769545851389cd7b65bf4ce8cb8df6350da2a0acf38eaefbad1cb13a54dd2b9a34d5548ceb77319904e5062d889c0effce0a5b48a56a51319a725baa81600bcc00283c5c5f204048b71b5b13be95ad75c3371958caa5476cc5cc3f8a98d15e8312ac5da7cddb02346599f194a598bcca4683f63f4e2d0a68fd801021280d9a3180cc6e24f1ccb8a56ed492fb8e35f0cd88
#TRUST-RSA-SHA256 9cf3308465e2e90884f93195abbc83fbfb0328463b9d368f5424890ae756069a256b1f8ed98da2697332a4eb27916aa9d17f608e5c02ec1d5f4fa26e0cab796a00b3c54b5ef712842fb1a723f51b369e0b44be13f20b015999141e95736c805510de51c1b9c29bb4ef94f204bb7e429ce267e70dd8070dbed0d0229149becc163bf1dc68bd651bc795bfdb99d1cfa78a15d86441b4c96cae750bdc08173899fb4a169f3b2eeada402bbf549fa7394ebb9b7f8de6067cc133e7ad4d436f5823dc04b7cd9664efbb85850a06732491bea8cab94e9d9a87e6a6723fdbe1f01dbbceaece014371b6a27ad70b2bc5d5a7dcbf37c334c58e4873aaa0b2011055f7ca26555492bd8df083162626571f5b679f7257929e2080f921e12506d66425d9911bdd62cb31fdb4bdd7473d97b1096d9308289aec10464b364409475fa2250cf8585d130e9b93ef7c66ed050125d21636c4e141b76be212f2c548eab1383d21fb65f4cbdd4389c629b9566e615859bc7672e0a1988189a3c6bb789cc6d50a3f79079437b058e69fa6de39381f7127bb818ce8ce5ebed9d2b132d375464e8aaf501db35a0976e01024641f93528db400553da9fd63c243d12e8ef19e0f7f0d2430390b822a50eb9a9d87b9d2e0a2e540d0c8586569edd3e27d9d9567bff96d3328259460c04214e221c3cfbb4ce389c77617ed68320ada93e37b5ea5d974e79da597
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(15890);
 script_version("1.18");
 script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/01");

 script_name(english:"Hydra: VNC");
 script_summary(english:"Brute force VNC authentication with Hydra");
 
 script_set_attribute(attribute:"synopsis", value:
"It may be possible to determine VNC passwords through brute force.");
 script_set_attribute(attribute:"description", value:
"This plugin runs Hydra to find VNC passwords by brute force. 

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

 script_dependencies("hydra_options.nasl", "find_service1.nasl", "doublecheck_std_services.nasl", "vnc_security_types.nasl");
 script_require_keys("Secret/hydra/passwords_file", "/tmp/hydra/force_run");
 script_require_ports("Services/vnc");
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

port = get_service(svc:"vnc", exit_on_fail:TRUE);           # port = 5900?

st = get_kb_item_or_exit('VNC/SecurityType/'+port);
if (st == 1) exit(0, "The VNC server on port "+port+" is not password-protected.");	# No auth

# Check that the VNC server is up and running
soc = open_sock_tcp(port);
if (!soc) audit(AUDIT_SOCK_FAIL, port);

r = recv(socket: soc, length: 512, min: 12);
close(soc);
if (strlen(r) < 12) exit(0, "Short read on port "+port+".");
v = pregmatch(string: r, pattern: "^RFB ([0-9]+)\.([0-9]+)\n");
if (isnull(v)) exit(1, "The banner from the service listening on port "+port+" does not look like a VNC server.");

timeout = get_kb_item("/tmp/hydra/timeout"); timeout = int(timeout);
tasks = get_kb_item("/tmp/hydra/tasks"); task = int(tasks);

empty = get_kb_item("/tmp/hydra/empty_password");
exit_asap = get_kb_item("/tmp/hydra/exit_ASAP");
tr = get_kb_item("Transports/TCP/"+port);

if (get_kb_item("/tmp/hydra/service/vnc")) svc = "vnc";
else if (get_kb_item("Hydra/services")) exit(1, "The installed version of Hydra does not support the 'vnc' service.");
else exit(1, "Failed to get the list of services that the installed version of Hydra supports.");

i = 0;
argv[i++] = "hydra";
argv[i++] = "-s"; argv[i++] = port;
s = "";
if (empty) s = "n";
if (s)
{
  argv[i++] = "-e"; argv[i++] = s;
}
passwd = get_kb_item("Secret/hydra/passwords_file");
if (passwd != NULL)
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
  v = pregmatch(string: line, pattern: "host:.*(login: *.*)? password: *(.*)$");
  if (! isnull(v))
  {
    l = chomp(v[1]);
    p = chomp(v[2]);
    report = strcat(report, p, '\n');
    set_kb_item(name: 'Hydra/vnc/'+port, value: l + '\t' + p);
  }
  else if (line =~ "^(Error: |Sorry, hydra)")
  {
    errors = make_list(errors, line);
  }
}

if (report) security_hole(port:port, extra:'\nHydra discovered the following VNC passwords :\n\n' + report);

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

  exit(1, "One or more errors occurred while running Hydra against the VNC service listening on port "+port+".");
}

if (!report) exit(0, "Hydra did not discover any credentials for the VNC service listening on port "+port+".");
