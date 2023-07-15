#TRUSTED 48d7583d75f7a073e48208683b0148d103d35613def291411fc430d3ed9a84b2acfa521ba670ab621f61426f612f66efb00d3eaf23ce18107827030e8bf823de524f5b712ee13ac65ffc38eb039ce5a54250d2c52ba1e654612f85add8518666dbe1854d1d8cfa2923e3f32ad2578487146460f9932a0d1c1d968721b1a0ca8d29dd4c0d35a5179620d529e69be354d2833403b5ef51d991425f832df4badc359141c1b665157db8c51075bcc3d44fa4e20da8d6fb8795625bf8ba5a95c6b792703b6a0904f945ec54f532248a94232cfdc34776c342838fcce109580b8497847ce1331bbc14319a4e11232a9ded9178489a114915e2a562dda39acfc0594727df1b08b53a7c6055847f6b892588d2107b20845dcb356faf49497bc156849ffe63aeb258a6ab7616fb746eacbe7a349344cdb67f27999b355b843ef3ad1ed5771c59bfa90a3ef6ca30447f820c4ae7c78ef3d15e676ecec017aca6520ed39d6dfa2e3d97f6d6af3d54904a838ac2790f80d29f513e3708f7bd6eb99fcc38d48085dd8c37b2162bd7b98c74300fd68123f6726d551ec985f8a498603ea29280187c156a50ceb0178c7071cd022f16ae930e310fe1830e6f0a3c40e151e363961c59da231124ccdf69418df0684d842f7df9d0a6eb84217be9fd8f7893fa037a84ec762db6aa917f42183bf1dcc7edf3a70293fe319eb7ca5c7dd84410537e88c5
#TRUST-RSA-SHA256 ae36581bab66bc2f6af189165211d18ee507e92e12bb5caa1be357e340b3ff9b66abee61a7819202bda5de7c01be750f48f77d2fc7f3ba676d8f109afa04a30a54fddab8ca592e1de9d09e59c4d20b28dd6331e3e5b62ea23cb9ee66fa1e63fe2097c68a410f4d70bde1790b43c594366e06c51d5b0a266eaad2a1936451d3fac5941cc7c6326fd201eca1bd317a74db936dc449b9c07204f3c3cf14c0e277162817115179b483e58119581a450d0f422f21d44acd8dc3a25fcdc4cfd35dd4e630c9bcec885d7e40d6d0f55fbad0a63d0ba37e1084099dc869f5a990cb728341c414c3375064fd60706759d1bf822a538b89d17cc63c89d4e1d86e0774800caab124e81cfc435c86f410589b87cd67483f9534f59d0d4c179e59a18ddbadba7ffb8b52d0d2ada1c035893dc4ef99e3becf9cb721877ddf5c686cd5793dabf76c322928a7981c2752d71264cfcdda1e6cdafef76b1ff2856646c7a1284a6b093e194dba8257ac4eb73bfb50b919432f2ad569991529c8873c904014024c3bec0a5e846777926a18ee57b1f5c1623b60693d1ce9b8fcce24a6b16c9a914cf1fcb41aad3b92ba039018272f2aa61889753d351fd69fd5dd19c3f21de275a845d2d780d0463ab171fd72653695bb2c10e97e4da901c240bd6a0c7932fc39ff2d3ac86c87c0233df1eed53a6e13c5a9a2215f139684b1806e667a78b6b0a5c894e149
#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include("compat.inc");

if (description)
{
 script_id(18660);
 script_version("1.19");
 script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/01");

 script_name(english:"Hydra: PostgreSQL");
 script_summary(english:"Brute force PostgreSQL authentication with Hydra");

 script_set_attribute(attribute:"synopsis", value:
"It may be possible to determine PostgreSQL passwords through brute
force.");
 script_set_attribute(attribute:"description", value:
"This plugin runs Hydra to find PostgreSQL accounts and passwords by
brute force.

To use this plugin, enter the 'Logins file' and the 'Passwords file'
under the 'Hydra (NASL wrappers options)' advanced settings block.");
 script_set_attribute(attribute:"solution", value:"Change the passwords for the affected accounts.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_attribute(attribute:"cvss_score_source", value:"manual");
 script_set_attribute(attribute:"cvss_score_rationale", value:"No CVE available for this vulnerability.");

 script_set_attribute(attribute:"plugin_publication_date", value:"2005/07/10");

 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_set_attribute(attribute:"thorough_tests", value:"true");
 script_end_attributes();

 script_add_preference(name: "Database name (optional) : ", type: "entry", value: "");

 script_category(ACT_MIXED_ATTACK);
 script_copyright(english:"This script is Copyright (C) 2005-2023 Tenable Network Security, Inc.");
 script_family(english:"Brute force attacks");

 script_dependencies("hydra_options.nasl", "postgresql_detect.nasl", "doublecheck_std_services.nasl", "postgresql_unpassworded.nasl");
 script_require_keys("Secret/hydra/logins_file", "Secret/hydra/passwords_file", "/tmp/hydra/force_run");
 script_require_ports("Services/postgresql", 5432);

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

port = get_service(svc:"postgres", exit_on_fail:TRUE);      # port = 5432?

if (get_kb_item('postgresql/no_pass/'+port)) exit(0, "The PostgreSQL server listening on port "+port+" is not password protected.");

timeout = get_kb_item("/tmp/hydra/timeout"); timeout = int(timeout);
tasks = get_kb_item("/tmp/hydra/tasks"); task = int(tasks);

empty = get_kb_item("/tmp/hydra/empty_password");
login_pass = get_kb_item("/tmp/hydra/login_password");
exit_asap = get_kb_item("/tmp/hydra/exit_ASAP");
tr = get_kb_item("Transports/TCP/"+port);

if (get_kb_item("/tmp/hydra/service/postgres")) svc = "postgres";
else if (get_kb_item("Hydra/services")) exit(1, "The installed version of Hydra does not support the 'postgres' service.");
else exit(1, "Failed to get the list of services that the installed version of Hydra supports.");

db = script_get_preference("Database name (optional) : ");

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
if (db) argv[i++] = db;

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
    set_kb_item(name: 'Hydra/postgres/'+port, value: l + '\t' + p);
  }
  else if (line =~ "^(Error: |Sorry, hydra)")
  {
    errors = make_list(errors, line);
  }
}

if (report) security_hole(port:port, extra:'\nHydra discovered the following PostgreSQL credentials :\n\n' + report);

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

  exit(1, "One or more errors occurred while running Hydra against the PostgreSQL server listening on port "+port+".");
}

if (!report) exit(0, "Hydra did not discover any credentials for the PostgreSQL server listening on port "+port+".");
