#TRUSTED 99818b7aeb03cf19beb90ae3dafaf92623467fbebc8907487ee797b9b3f53cd49b115f8d0d635f6624e297a95d9a3fa9e9ae337548c4a68f8f2954ab4dfacb6001e02c848bdad263a47eb5a508c5a0f0b0289861d3711d2bfc2ae4b85ceb027623934af5201c1e8507d9c60282fff567d435fb0f607c7781df51c10e09c18af46a03f512b99468f07cbb66f65938ec84097e51264d38be23d3fd10d23a309a939261dca83a6872c40013f0da952dca83984e375ffb0d67504bb4b2bd77c03eee908f90d02bd4236de2f067b69b3b5d6ebb799b684c2b14e8955b60f65829b5d3f771f9e0ff7949a591df2138e59b52ba2266477ab58548c82633145953bb4e84c28f54ebfc8ecc5728ba547110c8e9d5e026f815915f4ffd6589d9c846bfa46369e3bcdfc9dac69ccf0ce5ef853a91e7f031aadd4f19bc2828738736559d4f1d3c1c3de8c0f1216e889f2e71e1153ac54a82f84bf7dbf6e5bb4ca611db95a95fe033b3091541c82b3f79577b803480e20a0fec1bf81e0cd5296f9d4688c629b805bd927806d1de6f100e0251eef286bbbeb416225ad8fdfca44368d854f3452e81546ba99507baac30dd746aa7f7eb8393656482366e56edfba654c528d565508a2343794992d11171def9d6d10d3c6f2db04d4e4ba75d2bda421c9a73c8345db8d71c27a05b3fa250bdff893e40eaf90298596ed027ca71a42c6c68779e5185
#TRUST-RSA-SHA256 4393c52419eca4aff27196113e988c43d2fb469cd20b071121cede7a2058bffa773be94998201dd73bc43453ed9a3c7eed7115b3de3c54a826263f0344cfaf34e0e89fc09e56ce99fe7dd7654c1b77ecf3cdc8d14602335a7da45b4ed2ed9d2f3d1a38b9318bbccccbb94d2b36bd4a14e531fb0d4ecda86063d66784d224317570648daae2dea813a807e49b05e73c5b23e11c8c688a555f555bc8af09ffd4d335cd23097c0eadaada209537afc68caebdf449e32fae19da88599631f6576ea6883e8053b2f0a0a82f45dc9169971b86d4ecb77219d3752eed7418fc60be1dfcb8a401333e856c859838648d6d5a2ec618e0ffda344168655b5f2a63d1d62400f72aa452eb8b53bd6e01aa46611e5bb127fca596c3691ae133a41179d6d615359b7966526994bad123313f8041d0d13c2c2ccbd062c9d6a65fac4140d5c26649456156f70db054a5e186b4f3044a3df7d11202a17ac06e505751112550f2ca6b856b15fa06963a19f87770f8475a43cc35bb123f9f482cc961b0031ed37ddeefa9d9335cf5828791ed89a3ab4598cfacbc753863a2c59cacbc08d10567dae6eead789efac634ed3649a3920b88b8e01afb221ad575a416e08b1fb49d93aad0357dfe441f5bad36ebb6dafdd67e05e9c0aeadfdebac4d70006fbcdbb5809314c1ca9abbbef919cad042931d337344d727ee6d6cadbe7f35e821e3ab09c145d3ff
#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc. 
#

include('deprecated_nasl_level.inc');
include("compat.inc");

if (description)
{
 script_id(15870);
 script_version("1.20");
 script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/01");

 script_name(english:"Hydra: Cisco enable");
 script_summary(english:"Brute force Cisco 'enable' authentication with Hydra");

 script_set_attribute(attribute:"synopsis", value:
"It may be possible to determine Cisco passwords through brute force.");
 script_set_attribute(attribute:"description", value:
"This plugin runs Hydra to find Cisco 'enable' passwords by brute
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
 
 script_add_preference(name: "Logon password : ", type: "entry", value: "");

 script_copyright(english:"This script is Copyright (C) 2004-2023 Tenable Network Security, Inc.");
 script_family(english:"Brute force attacks");

 script_dependencies("hydra_options.nasl", "find_service1.nasl", "doublecheck_std_services.nasl", "hydra_cisco.nasl");
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

soc = open_sock_tcp(port);
if (!soc) audit(AUDIT_SOCK_FAIL, port);

r = recv(socket: soc, length: 1024);
close(soc);
if ("Password:" >!< r) exit(0, "The banner from the Telnet server listening on port "+port+" does not have a password prompt.");

# Logon password is required
pass = script_get_preference("Logon password : ");
if (! pass)
{
 l = get_kb_list("Hydra/cisco/"+port);
 if (isnull(l)) exit(0, "No account was found by other Hydra Cisco tests.");
 foreach pass (l)
   if (pass)
    break;
 if (! pass) exit(0, "No account was found by other Hydra Cisco tests.");
}

timeout = get_kb_item("/tmp/hydra/timeout"); timeout = int(timeout);
tasks = get_kb_item("/tmp/hydra/tasks"); task = int(tasks);

empty = get_kb_item("/tmp/hydra/empty_password");
exit_asap = get_kb_item("/tmp/hydra/exit_ASAP");
tr = get_kb_item("Transports/TCP/"+port);

if (get_kb_item("/tmp/hydra/service/cisco-enable")) svc = "cisco-enable";
else if (get_kb_item("Hydra/services")) exit(1, "The installed version of Hydra does not support the 'cisco-enable' service.");
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
argv[i++] = pass;

set_kb_item(name:"Hydra/cisco_enable/"+port+"/cmd_line", value:join(argv));

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
    set_kb_item(name: "Hydra/cisco_enable/"+port, value: p);
  }
  else if (line =~ "^(Error: |Sorry, hydra)")
  {
    errors = make_list(errors, line);
  }
}

if (report) security_hole(port:port, extra:'\nHydra discovered the following Cisco \'enable\' passwords :\n\n' + report);

if (max_index(errors) > 0)
{
  msg = '';
  n = 0;
  foreach var error (list_uniq(errors))
  {
    n++;
    if (n < 20) msg = strcat(msg, error, '\n');
  }

  set_kb_item(name:"Hydra/errors/cisco_enable/"+port, value:n);
  set_kb_item(name:"Hydra/error_msg/cisco_enable/"+port, value:msg);

  exit(1, "One or more errors occurred while running Hydra against the Cisco telnet server listening on port "+port+" to brute-force 'enable' passwords.");
}

if (!report) exit(0, "Hydra did not discover any 'enable' passwords for the Cisco telnet server listening on port "+port+".");
