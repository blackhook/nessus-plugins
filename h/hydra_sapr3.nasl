#TRUSTED 0e47bfc86b62c8d175bc60414faddc8c8ab4de4a4a8cd919d6a2c9bf00d7fa11ccb1d7c43ae1b7d6e6e7e74d104dee02d38b4df24bbee1c3695bfc3853b3b37e119a2cee7d94a3aabc27fefd00f2344c53400b37ac9d731e0ec48e87aead47065e76cea62ffa9574a5265758f26b1903cd9c1f752b9e5514f916e9b8bfda60349be751d4f51d65b871fba571e9b01778c1f7bfea5dc5f61692218203a5dd040366ed5c259e79d8a70f69e1d91de9a66f633d98c05f92499bb1b5d5b6aef01130d5884fc0bd70374949ef2908cb9557efc0fdcab79bb584f453a9b6337ad076b8be5eb743a6e256af7b49a627d2bd926e58c5778c42455522d8f4f4471edee2913cbf35698a3dacc7809ac6c3c6590a411e057e3d448c92e81cb589a8139d2219193870622be0570a00ac3349104a8e50f32c29aa010f19263d9eb65f36cdab16a2e4b33730cad06d5e88a54b6fe746af7e552a24d257bc551038cf792a2dfc77bb6be0ca5290933032f212f5e903840bf6144cf9d6b1d018ba221f2769b06451ca438607e6bdc550bad5a8c62ecca410cdff16dfce1127265b76b425544bc7ff185dbcaf524a45a1fe1a68f0038de4fc19c328386c1c1d01dfdc4a8f8bc8baf49e649e280709dfef0c4050c870030a5f146511dfb97fd66041441e124a63247622ccf5f7db4fa718e7b3b403cb42fd2cacc05720c00169cdafe5e33aff2b5c62
#TRUST-RSA-SHA256 7ceb4c46a3a41fcb8444f1ca12468d1bd4182224ec9a02111aa80d8f6a98ab0a508331fa3d57f3bcd17cefebe755c78f69a7a0e7d51f4bf13fdbb087c4f2f1b5b4ba87c330cb4a0c7f34a08d9620cb5972d450d79c9a4852fb4ebc63220d4edebf8513f0685e7c08c05658beddd78fe3d24b70eee956bf15a2f005a3f483a2c824cdf50a84f93b52a34008bfa4d77ff877911240468fe31dc44867d6ce6ab90180de6145dbc48bbeead095b88b74bae908897127b0f217ff2efcc629933da88e9a5000a47ab4c91de92e380f9310cdf21c3a5a333f8628240050bfaaf80a6bc22c46093cd94bf0060871059d03f8ca05d0053472eb6b13b3df5b2461c312a2579b4807bec2cb8d6de016bcbb3c94a6e8cdf06fc2c952c5bb1b80cdd5d7f68ba616a073864c3d03c0ca3e87e98ba025401c839d5f76b614185e3fba89964add9da8ba6a53409751908791d68a8f9bf59e3fe3fcadb70232f31ea6c522047bb5bacb1ed7bde78a3fc7f8606538a3a2d656c6d86ac3387a8ba25465dba7e7f0c4df8b1efd4acc3dd185b3cc882b7746739b3924c202e50ea9962c76ba1f8c3e6d35400a8a5c90b2631d02e6aa98144181a6f8284f21fe2b009151ff23933b8d9cb89156e9555becb6415ff2b000cb5bd13e5fc26a1167094a6b598d317caf71b1e614946ef76fbc613f5f257053b71c6dfb664554a5c5772243578919ae969ca8f9
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(15883);
 script_version("1.19");
 script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/01");

 script_name(english:"Hydra: SAP R3");
 script_summary(english:"Brute force SAP R3 authentication with Hydra");
 
 script_set_attribute(attribute:"synopsis", value:
"It may be possible to determine SAP R3 passwords through brute force.");
 script_set_attribute(attribute:"description", value:
"This plugin runs Hydra to find SAP R3 accounts and passwords by brute
force. 

To use this plugin, enter the 'Logins file' and the 'Passwords file'
under the 'Hydra (NASL wrappers options)' advanced settings block.");
 script_set_attribute(attribute:"solution", value:"Change the passwords for the affected accounts");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_attribute(attribute:"cvss_score_source", value:"manual");
 script_set_attribute(attribute:"cvss_score_rationale", value:"No CVE available for this vulnerability.");

 script_set_attribute(attribute:"plugin_publication_date", value:"2004/12/01");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();
 
 script_add_preference(name: "Client ID (between 0 and 99) : ", type: "entry", value: "");

 script_category(ACT_MIXED_ATTACK);
 script_copyright(english:"This script is Copyright (C) 2004-2023 Tenable Network Security, Inc.");
 script_family(english:"Brute force attacks");

 script_dependencies("hydra_options.nasl", "find_service1.nasl", "external_svc_ident.nasl");
 script_require_keys("Secret/hydra/logins_file", "Secret/hydra/passwords_file", "/tmp/hydra/force_run");
 script_require_ports("Services/sap-r3");
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

id = script_get_preference("Client ID (between 0 and 99) : ");
if (! id) exit(0, "No Client ID was provided.");
id = int(id);
if (id < 0 || id > 99) exit(1, "Invalid Client ID ("+id+").");

port = get_service(svc:"sap-r3", exit_on_fail:TRUE);        # port = 3299?

timeout = get_kb_item("/tmp/hydra/timeout"); timeout = int(timeout);
tasks = get_kb_item("/tmp/hydra/tasks"); task = int(tasks);

empty = get_kb_item("/tmp/hydra/empty_password");
login_pass = get_kb_item("/tmp/hydra/login_password");
exit_asap = get_kb_item("/tmp/hydra/exit_ASAP");
tr = get_kb_item("Transports/TCP/"+port);

if (get_kb_item("/tmp/hydra/service/sapr3")) svc = "sapr3";
else if (get_kb_item("Hydra/services")) exit(1, "The installed version of Hydra does not support the 'sapr3' service.");
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
argv[i++] = id;

set_kb_item(name:"Hydra/sap-r3/"+port+"/cmd_line", value:join(argv));

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
    set_kb_item(name: 'Hydra/sap-r3/'+port, value: l + '\t' + p);
  }
  else if (line =~ "^(Error: |Sorry, hydra)")
  {
    errors = make_list(errors, line);
  }
}

if (report) security_hole(port:port, extra:'\nHydra discovered the following SAP R3 credentials :\n\n' + report);

if (max_index(errors) > 0)
{
  msg = '';
  n = 0;
  foreach var error (list_uniq(errors))
  {
    n++;
    if (n < 20) msg = strcat(msg, error, '\n');
  }

  set_kb_item(name:"Hydra/errors/sap-r3/"+port, value:n);
  set_kb_item(name:"Hydra/error_msg/sap-r3/"+port, value:msg);

  exit(1, "One or more errors occurred while running Hydra against the SAP R3 service listening on port "+port+".");
}

if (!report) exit(0, "Hydra did not discover any credentials for the SAP R3 service listening on port "+port+".");
