#TRUSTED 1e4adcf47fcacc9a024d50ae933d1db69fead45b6b0b3b45a74de7ce5811335216add39e265bbd1cd1b0a426fa3e8f6f0eba473aa4f84ed55b6e27122866a93baf0dd3d212dab8847c9731e77a8b582e490c49315d01a7afaae6852ec884c62f1bd754191f2172cdc4f49f3f3731b0464876d8a659ec539f4419bcc6573012fb7343e53e1c268ca017f6a5332355d15744e16200fa37c24c598802fe13a36b7c6e542ba67665df010588d802b08e76f3e6a035d8a9a32c6797a8b0f1abdb493ad9246858b661a7190588130c23af42c9783b82a327d96a31f89766b2ee699d180a307b2ed88b63d32b05c14ebf982d10b893e3e5eb1729e4645509f6b7f0d9580da7ff2fb7d0d52b494d7b5fe49e752e69f4b70f4c574010951a163eb79cbdc0851b341b03ae9e112094208673b908343eacd25b5691de01a56fcc44a62fe3e1b06aa6c29e111fe2aa72a19a0a87913bdf6a60ece07e4ae09108ed2379aa4114efdd5f4ebe6c228690fb2e61d4df3a1feea1866e14a6384ff96e92589d6812afcbd16dd79ffe6d0d810f6be21bf9ba5fa4cd656d02ac1caeeb1fdf387f3136de0de95fb3ee43f4011afd147eeef1b4fd396f5c4769721e1b63b4953da3fbb43b0304cc7b34cd76ddd1e5a6f95ffbca81ce57d90831a81fc8734a2e2cbe51743a7313bfb423f9840cd240f895ce12c7c30918373bb4e8528b51a7f5f071769f58
#TRUST-RSA-SHA256 14faa1a0d2aceb9b9a33a538a44b52ed5083d5e4f08f69685c6f6c2da55f0ddfe062f5bd6ea2d3ecfbfbd09f420b7c58b677d1b64f1cf85e7a4fd774a2ea26cd6c57d99a602d8a4c3291db5b5fd34c9d357503eb5c3e97d7157ca77e49d080d2256f5ebb904e7af62ef5cffebdce95d1b4ac5bfee7938f8234205a5735a3d20699bc63a46546712069cdcce04ac317067591f1dc825ed799a5f58decb3ddc7e621c2d6455eb81ff5e74f6ae6c4142c100c7f881c91284db4762038d6bf4796fdf3d7331d3ce5d9f40b86ca321b8cbd026e8b7ca0c2d42304831db66804b26e5a9a32b6e41236ec734968754d7949a6b4978c098c8c0998b7522a6c65096a3e58f86277170fa82ec18c9d1ec5a1f7f70d74cbf560c054a94e52fc00f908c20266c4e6910e9f3c6492f5ea7697692b00a8539d12e598c5bf5384ffe9b67536c11d922e9b7ba34336f561c44aca4828d7f65623ca50e6e252ee27f77604c55017b39decf5e3d1a18789b1c395ce917bf0ec63d9602157cf4660be39425c93c90a0a1bfec94bf5f39c011a8d61697bc5dd29a39c131d0204549711ce2dd63d600b008f12ea3d9a8187444d91644f5861425df079624b5848583a9d8d9d73b6170bf3be2a7dc5f060287a27d80293993ebe058a7ba3e3eb093d09b311469cc107e42b68b29b8683c23c66fdb08a84e0f16031ca4f3d01b76dea1f80eacb91e124d233
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(15887);
 script_version("1.18");
 script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/01");

 script_name(english:"Hydra: SOCKS5");
 script_summary(english:"Brute force SOCKS5 authentication with Hydra");
 
 script_set_attribute(attribute:"synopsis", value:
"It may be possible to determine SOCKS5 passwords through brute force.");
 script_set_attribute(attribute:"description", value:
"This plugin runs Hydra to find SOCKS5 accounts and passwords by brute
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

 script_dependencies("hydra_options.nasl", "find_service1.nasl", "socks.nasl");
 script_require_keys("Secret/hydra/logins_file", "Secret/hydra/passwords_file", "/tmp/hydra/force_run");
 script_require_ports("Services/socks5");
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

port = get_service(svc:"socks5", exit_on_fail:TRUE);

if (!get_kb_item("socks5/auth/"+port)) exit(0, "The SOCKS5 server on port "+port+ " is not password-protected.");	# Not authentication is required

# TBD: check that the SOCKS server is up & running

timeout = get_kb_item("/tmp/hydra/timeout"); timeout = int(timeout);
tasks = get_kb_item("/tmp/hydra/tasks"); task = int(tasks);

empty = get_kb_item("/tmp/hydra/empty_password");
login_pass = get_kb_item("/tmp/hydra/login_password");
exit_asap = get_kb_item("/tmp/hydra/exit_ASAP");
tr = get_kb_item("Transports/TCP/"+port);

if (get_kb_item("/tmp/hydra/service/socks5")) svc = "socks5";
else if (get_kb_item("Hydra/services")) exit(1, "The installed version of Hydra does not support the 'socks5' service.");
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
}
else if (!s)
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
    set_kb_item(name: 'Hydra/socks5/'+port, value: l + '\t' + p);
  }
  else if (line =~ "^(Error: |Sorry, hydra)")
  {
    errors = make_list(errors, line);
  }
}

if (report) security_hole(port:port, extra:'\nHydra discovered the following SOCKS5 credentials :\n\n' + report);

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

  exit(1, "One or more errors occurred while running Hydra against the SOCKS5 server listening on port "+port+".");
}

if (!report) exit(0, "Hydra did not discover any credentials for the SOCKS5 server listening on port "+port+".");
