#TRUSTED 1aaba6f83f9087c0df431d67992dd007678ba6f328b961a070c7cb5d904ef5363e41f19a2eea80f976f0ca3d4b02f69af34c8838ee0f694fb36a0abb3ed8fdc041bb810dba40beb21e77b732569e144d08ff630cdd8fbefe0584832c8674654417ac3e6e9a1651ac45dde7950e66377dcdc3bbd42b160862fa6a2e741b4d12d43b22b2f2c4f5f3d4a325857d0e37f19f5db5cb6e0ff9e883447c2c669d398eda20cfcc33e4e383ef31d2b1b6447ac913ca27c02cdaa33d9ca4f4080961c7474ab096422aef3a0f56814c26f6ee872c1c6f80b12eb1e2c12112c707fecb397a4ae544da77facc6efc9fd1f489744ee79b1dcb5d100cefe28ff28b51470d7b5631909f26fa88d3001cc881c80e5cb099118aed3b3a8ebcdb9a40e99850be8db45c00f0e3f491f158b5290b5eaec631fbde6ec5d92cf037912f9ead2382660ad335f511c50f7cb6f6a30ec404797bce5b053a2b95567a127a79c0eee7d66071efd00ba9109425b9aec28f68d06d1b2d59d084c25f3f705d5d734c2b73bc82a5bc7ea10b17e412266eeba9b95917175c8a9ef259eee8007209ceafb1f179b88df6b0c0f7faeeb5e31dcb20df69df46103626910a19b36ce10ea47ec6078e60fb44311a42a205f654cd2ea81e9052649935807bcaa9147a7dcf9cf7b04518689366f7026a55cb8d24cad711b1905335d3ee100d1b8cee08a421b40ea2f28cc078fbb3
#TRUST-RSA-SHA256 9ac881c87187256de60748908faf481f2521b041d2fa2105836d9ebb9c5727daf6bd35fb0decb23b31f4d7e513f3bbf8a96e31ee769d19058ca9af4c0ee5e40e22fbed54b8c0f1edf48cb8f0e497740b879863d4bbfc4fecfafab1d371fa65f44942abc54b1151c6e2f5ed626267905ae8936d8c4d5c1df3bb3831f925b0e0138194a127f06ea550a712ccdb870ca280e0a65745c23b217457e861bd8a34ea2ea0eeb7a4fd2c332431b76fe6b197bcdca167a7f2b52f8a925e99d1be5c266e17d15e994aa29a60e370943f664f7fe6d4c51ccde29e4ad5dbc14266aea5622653f9e0b53e1e5641617cd19dea9e14faf6298efb1cc0392e07d31c7f00a6936c75c0da8fbeb74732f22a35671e441260a928202d91942b01ebb3e0e45b1f10daf93b9778d7224367a57f943d2614a2dbcf655a524cb1918dba3f045db92768a882d84529ed8f978cd217c2aedb52aa6594682b8bb5e33ba4b6063569397393e36a87b49dd10649423b0af00a678e4f4134e9928e10f988fdf758bb5e461f0678a9da0d92d145c340d25764d40cb6227ec51d7642b496dc94600c0e17d6e43cfbe27815c3f8774e4ec5e84f2fc7353a0419ea790a8cf8e5acbd78c1200ea9bf8c3fef6500ad10bdec5e7e0aa1ab075d111196767fe61994242a69d3b973f25514f20b5a34cc040ed537d975dfbe770c29d23352891eb3a6659a3eed79e4e79495d4
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(18661);
 script_version("1.16");
 script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/01");

 script_name(english:"Hydra: MySQL");
 script_summary(english:"Brute force MySQL authentication with Hydra");
 
 script_set_attribute(attribute:"synopsis", value:
"It may be possible to determine MySQL passwords through brute force.");
 script_set_attribute(attribute:"description", value:
"This plugin runs Hydra to find MySQL accounts and passwords by brute
force. 

To use this plugin, enter the 'Logins file' and the 'Passwords file'
under the 'Hydra (NASL wrappers options)' advanced settings block.");
 script_set_attribute(attribute:"solution", value:"Change the passwords for the affected accounts.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_attribute(attribute:"cvss_score_source", value:"manual");
 script_set_attribute(attribute:"cvss_score_rationale", value:"No CVE available for this vulnerability.");

 script_set_attribute(attribute:"plugin_publication_date", value:"2005/07/10");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();
 
 script_category(ACT_MIXED_ATTACK);
 script_copyright(english:"This script is Copyright (C) 2005-2023 Tenable Network Security, Inc.");
 script_family(english:"Brute force attacks");

 script_dependencies("hydra_options.nasl", "find_service1.nasl", "doublecheck_std_services.nasl", "mysql_version.nasl", "mysql_unpassworded.nasl");
 script_require_keys("Secret/hydra/logins_file", "Secret/hydra/passwords_file", "/tmp/hydra/force_run");
 script_require_ports("Services/mysql");
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

port = get_service(svc:"mysql", exit_on_fail:TRUE);

if (get_kb_item('MySQL/no_passwd/'+port)) exit(0, "The MySQL server listening on port "+port+" does not have a password.");

# We should check that the server is up & running

timeout = get_kb_item("/tmp/hydra/timeout"); timeout = int(timeout);
tasks = get_kb_item("/tmp/hydra/tasks"); task = int(tasks);

empty = get_kb_item("/tmp/hydra/empty_password");
login_pass = get_kb_item("/tmp/hydra/login_password");
exit_asap = get_kb_item("/tmp/hydra/exit_ASAP");
tr = get_kb_item("Transports/TCP/"+port);

if (get_kb_item("/tmp/hydra/service/mysql")) svc = "mysql";
else if (get_kb_item("Hydra/services")) exit(1, "The installed version of Hydra does not support the 'mysql' service.");
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
  v = pregmatch(string: line, pattern: "host:.*login: *(.*) password: *(.*)$");
  if (! isnull(v))
  {
    l = chomp(v[1]);
    p = chomp(v[2]);
    report = strcat(report, 'login: ', l, '\tpassword: ', p, '\n');
    set_kb_item(name: 'Hydra/mysql/'+port, value: l + '\t' + p);
  }
  else if (line =~ "^(Error: |Sorry, hydra)")
  {
    errors = make_list(errors, line);
  }
}

if (report) security_hole(port:port, extra:'\nHydra discovered the following MySQL credentials :\n\n' + report);

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

  exit(1, "One or more errors occurred while running Hydra against the MySQL server listening on port "+port+".");
}

if (!report) exit(0, "Hydra did not discover any credentials for the MySQL server listening on port "+port+".");
