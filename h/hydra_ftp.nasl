#TRUSTED 2e98e0de1449354308313f05af0e2766352283503bb1020273fd93dcae9280fedd920311d10270c77aba62cf066c28453b5bc15c42742ff1c12d794ac9acd521fcdc73813abb260518748b24dec14617da9d39b5f8ed0549bb6a3d2bd8195036996a5168acaa18f3d39c314bf31526a9a85d3864d2de2975d87b65d248c0ae3a805f51aa8b1f67685c79e0732bc234afee03b479ecb7c24549b9356c79662d0f96069d06cccc081817f7e7f948221f292aa2805c85d214dc89ff60884a45dbda88e9e622462d4f39c52fdc23f825e9161e21abc45018c6975a08b459ff624a3ece14f68282c822d0f42179e82129ab1dbafd88a97ded2fdb0da022a0e87b156ab9dc2f6d410c377aa914abe22024fda48683f2dcdc495fa0f2aecfa27f5f6021c0c7c1dcb83ebc25546fe27e635bb1d71b2788ec8b9c964db146df98731e12d5060e369e0d35328630e6f3bb3ecd577061d195043c3733cdabddcc51ddb81c580d2db8a5ae5d80404b8a198501476fca67ee2bccc79172795d6072892bf65d91a575d44c63c3549bc8787d8060906672d107bb6abdc9607771ac2c66281abf9cc23febd30de12e391ce2b31a19a0f0d736d6af8a5f2f40ad3691fd2a7ad546a45948e008b63a50980332cce6fdfa3ad111f3fb19f715396c052996a5c62fd263752fb2cd5a37761b2e54668f582e514f60da8ecce897c6946627eaae58f76087
#TRUST-RSA-SHA256 93b9d999a7584a4f991201934d4410ea510da0bd3f59a96ccd460721fcd2a4fb4118fd224a002593444daf382ce78efc20f0aaf2867a7074eeb39a55512387c63a8e28fe7bcfb6d59b43774e1f6a5e0922eeb5a03455e797efe38b38d1ba30c6b3b3b801f120dfb6f777e5fec32f201509410e4fc78908a3dc507dcc51f1a408a2da397552bf96d4373e382e83ed3553db8ba43d98be8abe0219c84afff94cde82fa7f7f7bfdf216cfb5ac2f5efb2c79184eb24e7c7b3bb9e9fa67597f034ec2e89f59d451b91d7c8ebf405436acc16ea5b0c5297058ae4779e997fc4b348229d5673cc39e7a81d2e4469b11a471d2d623dddf39af55dada9f0a13d011b11c724f147b704943ce6854a06384212a201ccd43227b5903ad61bc5002b28c45c541109bb8b6c6bbd147dd5e8465974f677e4c2222a3f34f51cf377ff07ef151d36ed39bfd7ad205cd31b5115a7bbb361e7ead1d496e23489fcb48ba7e838b4735eb73a3cca874effde4139d9069c0dc429ebab57d1570643523a6521b6d1ece0935d4b58ca0ecc95352bf5e57abaceff0804d7c65784b999e8285be7a614cbc729adccdf74c7ac1f23e03340f9d0c10fff2eae0067d854874084c8e92736b666c5e1af8b2ec2b96fc5094603dd189921928e8685d0baa7b55319da6bc481972aee16c6f76f54d8a03775180983e9a6e17a309748a9b47ed1738de0b3f87746231e1
#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include("compat.inc");

if (description)
{
 script_id(15872);
 script_version("1.20");
 script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/01");

 script_name(english:"Hydra: FTP");
 script_summary(english:"Brute force FTP authentication with Hydra");

 script_set_attribute(attribute:"synopsis", value:
"It may be possible to determine FTP passwords through brute force.");
 script_set_attribute(attribute:"description", value:
"This plugin runs Hydra to find FTP accounts and passwords by brute
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

 script_dependencies("hydra_options.nasl", "ftpserver_detect_type_nd_version.nasl");
 script_require_keys("Secret/hydra/logins_file", "Secret/hydra/passwords_file", "/tmp/hydra/force_run");
 script_require_ports("Services/ftp", 21);
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

port = get_service(svc:"ftp", exit_on_fail:TRUE);       # port = 21?

# Check that the FTP server is still alive & answers quickly enough
soc = open_sock_tcp(port);
if (!soc) audit(AUDIT_SOCK_FAIL, port);

r = recv_line(socket: soc, length: 1024);
close(soc);
if (r !~ '^2[0-9][0-9][ -]') exit(1, "The banner from the FTP server listening on port "+port+" indicates a problem.");

timeout = get_kb_item("/tmp/hydra/timeout"); timeout = int(timeout);
tasks = get_kb_item("/tmp/hydra/tasks"); task = int(tasks);

empty = get_kb_item("/tmp/hydra/empty_password");
login_pass = get_kb_item("/tmp/hydra/login_password");
exit_asap = get_kb_item("/tmp/hydra/exit_ASAP");
tr = get_kb_item("Transports/TCP/"+port);

if (get_kb_item("/tmp/hydra/service/ftp")) svc = "ftp";
else if (get_kb_item("Hydra/services")) exit(1, "The installed version of Hydra does not support the 'ftp' service.");
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
} else if (s)
 exit(0, "No Hydra passwords file.");

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
    report = strcat(report, 'username: ', l, '\tpassword:', p, '\n');
    set_kb_item(name: 'Hydra/ftp/'+port, value: l + '\t' + p);
  }
  else if (line =~ "^(Error: |Sorry, hydra)")
  {
    errors = make_list(errors, line);
  }
}

if (report) security_hole(port:port, extra:'\nHydra discovered the following FTP credentials :\n\n' + report);

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

  exit(1, "One or more errors occurred while running Hydra against the FTP server listening on port "+port+".");
}

if (!report) exit(0, "Hydra did not discover any credentials for the FTP server listening on port "+port+".");
