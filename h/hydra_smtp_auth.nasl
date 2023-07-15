#TRUSTED 53b7e3b8107960edf9c263f7c872610b48fde821416ccf0e4b24d4fa878b872fcab658631c7dabfcba3d485065f06427d6bf38dadbf1c9fe240949afd31e17ea6a9a68b061708f6a3b43d8c5cba090ab351171752a1bc3358f1f98bfe0010b651df7e651d1e2b389e68b4df6c65a142bfec5f712bad05e536fbcc8d60b161e2760c3f855ecc542df659c4855290fa300851855f4b83c60e28f304328ce1e973a20a65c4046255899227309bcddd4b4026a8c1d14189174eeefbf922c75bb4c80792d1b3c0b3798f7c02cc75b2870e39edbc1968f95b062b802a93691c7c346ddc51a71e4477e39655b7c2e32733fb70b94395aa2738d96a96551520d963fdf0e74d76654c5dd2a9a5ba1ede40b60907b0c6b14b0c8da039e841f978b8e57f91b1cf3cf7758f3c81b8a0236d5b0be2ef9d47eab06059e6bbb698b1bc54bfb8a3b7fd7b9ae697225a73989baeaa3d0985acdd821d40bc820459d1e28d224d9565acbe1d7c9de1e3324c831ebcaa3fa400a99962073673c571e91362e1618d6072884e909250027b2159795e65503fb58484bddc502c3ca80e28398a7e6cfc0176c42f95e4653cd52a000bbb84969f4f0d5e31d5eeb31f10de0275e975ddb2720ef93e8b24b55524e487c7bb457c69a4ebc7b67d489bfc76077292b96e4a66a248b6b4e97807624c1e1d914cab478e318ae7e39cf08d596ea921a989b76df9d1f1d
#TRUST-RSA-SHA256 4d0a27f5d3713d3abddd39ae6b134f0375745efad6edb838ac2a6e8e3a785ecb25ff20ec53ee2c5b8dba5d72c3e85c9ff801dfb1f8d66a2a11715c847ce7fbe9479fbceb990a96517f5dc5443f6de9248817e49526ed056dbf5deb47591887e93cbd4ece644b51ca1f260ca94bd79154730ec55cebe5926f964c693b368a9ec4bf042616abf1a31ebcb22abb7629de5fae9c160967551261b1f99f07d8709cc4bfa2937e3fcc092c46bcb2b7a405930405dc1877fd7ad1c1777cb7902a4caa950c9885c3337029f3ef8e27b1648bcb313ed57dbf3dda9f0bd9f50cd7bcea3c545a104cb1048b8eeb35239541cc71498a44113057dc6f4665fbfc34216ea800986e9349c14fbfa95f9d024384e4232b032bf83e41db64e0adcb53c8d471dcbeefb0153fb41f01edfe4b8d0dd8871382b5c8e2f496009cd7afa984249b8a3504bd10449e499094c5e52d55d94ff12b4733251dec6ff0bd9d99201f980b7314cbcc614343aa271941115316439ef6733309dc4e335d24a8e23c9994c746adf70616e6426477d95c26c9942978e8ab282605fe621bd68fa458ad34067562ad1eea5bd8ddc79d19fb54ef58a29a348bdcf8071359289f0dc7e3907db6937f56d67a45c07b1bcbeeaad11ec21bc6174b9af534092b578de2c85a3386e85f6aa72fa883f1e61458d014446d51c3b047360d38b8f589e2d7e23205d29d70eba8d6da0cea
#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include("compat.inc");

if (description)
{
 script_id(15885);
 script_version("1.20");
 script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/01");

 script_name(english:"Hydra: SMTP AUTH");
 script_summary(english:"Brute force SMTP AUTH authentication with Hydra");
 
 script_set_attribute(attribute:"synopsis", value:
"It may be possible to determine SMTP AUTH passwords through brute 
force.");
 script_set_attribute(attribute:"description", value:
"This plugin runs Hydra to find SMTP AUTH accounts and passwords by
brute force. 

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

 script_dependencies("hydra_options.nasl", "smtpserver_detect.nasl");
 script_require_keys("Secret/hydra/logins_file", "Secret/hydra/passwords_file", "/tmp/hydra/force_run");
 script_require_ports("Services/smtp");
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

port = get_service(svc:"smtp", exit_on_fail:TRUE);          # port = 25?
# NB: Hydra will exit if SMTP AUTH is not enabled

# Check that the MTA is up & running
soc = open_sock_tcp(port);
if (!soc) audit(AUDIT_SOCK_FAIL, port);

r = recv_line(socket: soc, length: 1024);
close(soc);
if (r !~ '^2[0-9][0-9] ') exit(1, "The banner from the SMTP server listening on port "+port+" indicates a problem.");
# Here we could send a EHLO & check that AUTH is supported...

timeout = get_kb_item("/tmp/hydra/timeout"); timeout = int(timeout);
tasks = get_kb_item("/tmp/hydra/tasks"); task = int(tasks);

empty = get_kb_item("/tmp/hydra/empty_password");
login_pass = get_kb_item("/tmp/hydra/login_password");
exit_asap = get_kb_item("/tmp/hydra/exit_ASAP");
tr = get_kb_item("Transports/TCP/"+port);

if (get_kb_item("/tmp/hydra/service/smtp-auth")) svc = "smtp-auth";
else if (get_kb_item("/tmp/hydra/service/smtp")) svc = "smtp";
else if (get_kb_item("Hydra/services")) exit(1, "The installed version of Hydra does not support the 'smtp-auth' or 'smtp' services.");
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

set_kb_item(name:"Hydra/smtp/"+port+"/cmd_line", value:join(argv));

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
    set_kb_item(name: 'Hydra/smtp/'+port, value: l + '\t' + p);
  }
  else if (line =~ "^(Error: |Sorry, hydra)")
  {
    errors = make_list(errors, line);
  }
}

if (report) security_hole(port:port, extra:'\nHydra discovered the following SMTP credentials :\n\n' + report);

if (max_index(errors) > 0)
{
  msg = '';
  n = 0;
  foreach var error (list_uniq(errors))
  {
    n++;
    if (n < 20) msg = strcat(msg, error, '\n');
  }

  set_kb_item(name:"Hydra/errors/smtp/"+port, value:n);
  set_kb_item(name:"Hydra/error_msg/smtp/"+port, value:msg);

  exit(1, "One or more errors occurred while running Hydra against the SMTP server listening on port "+port+".");
}

if (!report) exit(0, "Hydra did not discover any credentials for the SMTP server listening on port "+port+".");
