#TRUSTED 87d46d18e6028260f26c92826826440fa9ec3da7433fd266c0739a5c32cf85c4be208f0d40177fb77669ac3e693b5eddd74a0e38409e687f44296e6200fb7b22aee3bf1c9d542f5805ddf0b2196240172a2be5373392f4404ac87e18f83aa9235dafbf7459b03d13f5a9f3e82f62420452b3047b848b6103759e00a6a449830414f6fa772a95a7cc2a69550271e80553320a4fda012e9b040531fdff3da6235a41e795e79e8f4c01483b8bc7a06c9745d9cdc0c73acf07bd7035e17da9ebb085d95d18cac90e6efd332380bed5c193201d6dc6a6738eb25e75489fd5a933433b3e0b2ece15b1a3a85c3999a93ec6b68e9b44a539d2ace69fd29ea309a4497c7765fe311a1197b6bf82b429860260fe203e985d3bfc830c125ea46d408cd594d71505612e149088ffdc2eade44e5959d59fd1f76126befe5879af88cdb1b856aaf8fdf2a3f1959813c77bb5668e5b4d05cb8df6cec7bc375b8783bbe3265154688fbd35ced4dfdb986cc00f4c37610bc6865372883e284ce7c10487df01a8f5fcd47057d52ba580665dd82958d10215d96b0c51aea01e142c05f034f7d80d4406a2a1ed49a7e8f0da623c5288fb9c7f16cab8f0b5dc843e9bcfb256ac76b64692ff63197a8979cfc7db3e30f639b2a8f3dd1fd2c84d091b596a23c2db6b8d5e75e15aeccce53e929ee56ce08428ce2f38381861898b663dc6178e90277e03862a
#TRUST-RSA-SHA256 851216a47a05255c46669d07fcb891426c5fb8fd80283ee6e7db3ad7f157676883fe8f81b57f8260aa7024c824d46c31ea59d59d02684e91a0ed027c1d5b9c7dd9e60ad9bb943eeef7c0b30eb0e2c592ecf35dee65d64b6945a29848d7744dd665badb216ac6869e8095c22d42b51d1fd58c855bbec9b1566c55db9e93c354afae8253d8abf41cf237b76b3aa5f0352807276fb5ea96d72413e30244d6262c6e524b72f8a197c7d59162efd40b50cac0c64b58b15110949f8a148682464fad610dc83f4066aaab180568b99247b2ad4c2ab615a6de7f5aa68d99288e6bcd77a51b2da83a7670672b83f618853b3a78e679213f4a58cb0f4c9e1517735f5b254a5aab7b8ca01ba739120806c0d6fd1359cce5bba1565e922cfb9295957214cae23b51c2b9bd72f1c817365c7b45204ce6398f872866f6bbe5ed25fa8c55d39140e6364818c7c6cb387397b2bfc6a67b7273f961991c5d7b49eac6d0ec2a1ac59e96923577ac06dd242a53d40ae5f1ad1f262b4c76d81c96d956cad332190e25833f25402d8fd1a165da0d9adb613e6be2e420597b3c74e1965bffc77d55057593c8825226b0f006975831b1f1e7430ad5527da5e9d30778b0f9ad30bec16dcddab1245ba7f3b4160b54b7ea103d5d39643fa7b82370562c1b031299b8e11473390cb8eaaaa89eb50c53a7af3fc3f7ae1087e5572643416ddd6764a34c8d3a7aac
#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include("compat.inc");

if (description)
{
 script_id(15886);
 script_version("1.21");
 script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/01");

 script_name(english:"Hydra: SNMP");
 script_summary(english:"Brute force SNMP authentication with Hydra");
 
 script_set_attribute(attribute:"synopsis", value:
"It may be possible to determine SNMP passwords through brute force.");
 script_set_attribute(attribute:"description", value:
"This plugin runs Hydra to find SNMP passwords by brute force. 

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

 script_dependencies("hydra_options.nasl", "snmp_settings.nasl");
 script_require_keys("Secret/hydra/passwords_file", "/tmp/hydra/force_run");
 script_require_udp_ports(161, 32789);
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

port = get_kb_item("SNMP/port");
if (port) exit(0, "The SNMP community name is already known on UDP port "+port+".");
# Yes! We exit if we know the port, and thus some common community name
port = 161;
if (!get_udp_port_state(port)) audit(AUDIT_PORT_CLOSED, port, "UDP");

timeout = get_kb_item("/tmp/hydra/timeout"); timeout = int(timeout);
tasks = get_kb_item("/tmp/hydra/tasks"); task = int(tasks);

empty = get_kb_item("/tmp/hydra/empty_password");
exit_asap = get_kb_item("/tmp/hydra/exit_ASAP");

if (get_kb_item("/tmp/hydra/service/snmp")) svc = "snmp";
else if (get_kb_item("Hydra/services")) exit(1, "The installed version of Hydra does not support the 'snmp' service.");
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
  v = pregmatch(string: line, pattern: "host:.*(login: *.*)? password: *(.*)$");
  if (! isnull(v))
  {
    p = chomp(v[2]);
    report = strcat(report, p, '\n');
    set_kb_item(name: 'Hydra/snmp/'+port, value: p);
  }
  else if (line =~ "^(Error: |Sorry, hydra)")
  {
    errors = make_list(errors, line);
  }
}

if (report) security_hole(port:port, proto:"udp", extra:'\nHydra discovered the following SNMP communities :\n\n' + report);

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

  exit(1, "One or more errors occurred while running Hydra against the SNMP server listening on UDP port "+port+".");
}

if (!report) exit(0, "Hydra did not discover any credentials for the SNMP server listening on UDP port "+port+".");
