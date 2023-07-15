#TRUSTED 1ff8de43f4cc4696b42ad02cb83ef28ffbf1d73beefb6bc56f3915c10603dde8b08b459f7299da4950853e45a6f22d3b2d07aa4b374e9588b2b143688db295b528cd43b945345ed2324f40018338269bec49833628868ac63d3a3ba2db293fa118b97f0b2a63ba95c06e5b8ad1def5baa6005131853727b823973dd4bf577140db196022c07cd1bc8dd085e864d56b702ba6dd11105e2ff27a07dd094b9b69876216a82cd05d1510c8989ac89f3a4b82c2e524a48a2d99ff3f103edd5e217c5e2de9923e129bc6f1dde2935ffca0b2338774d97f7105d7a26db26d732979ded2cdcf60b58ecb650181027beabaaa61ccd69ac880dc1e795f900c6ce5878d05cdbf87d37d66b5e76491adbc0ca0a2e5bda5564b65e3854dd318cfa3a65268d2b757f82e47f1c4aeb0488eddf685a70e557dc9a8505c2a9b4e931ff7e85ab80b216c2fab302a57b924ef0dea0aaf6177c30674c1ca73de48616b3a9d6a9421b4447fe1151ffb9d4dfda61e7bace35090e887be9259928e7bf66406e112084cf846722cc204e0d75fc1cc4e4d24962aa3535a9ce63f1f32391205cbc15a11cb8619106a09eeb9a9d2938a966de53d5d2b9a7ed8b4b81b5df73516524ad483177124cbf5eacf45e5caf65438198d5dc009fb853265d422f6aeefa1cdb2de7d80d82de5be8e1f77e6d626f140f16b0306a9564d8960b5ad63902e5b016c02d29f4a7f
#TRUST-RSA-SHA256 9137ca4d66745fa57f4bb05cc229960026f1aaceb70513c47314c3ac88a659e057ead2621fa3066604dacd53bb6943c7d2ba6b4254d789686cd04a56bd28b793053a48182f7461a241ccb46696808f83f6fcf6e2b814bac643f771272f13c5fc785d8166d5afdd1dbe9691eff43775d881a76415e2b320b0a9b6106a607098b412741911cc61888f9cc59d8e2da3ecd3d8d0b0c5c5a87f936d1767f0fc97fc4da73050df40d8e626c5b3eab864202bcd78a8d887dc5398de953b884f9a1f57e90afc46f871d6abc754ab06f4805a12c02ee3e893349e540f175b9850dc6a631d45722b1dc701e0ecca1200e6dcbce04525733995982b3dd50ed4baeebcab6bce9276915c9b2d24b063ec0fa585c9d8172a7dbd7cb7ff4497ff1143f5f9645f39521e63115994b259cbfafbf892a45f51f96079b545557b88012d09f10f0ae34516ce251f7630273fdb4c502d00c4406a46679cb06f679f8e418ffadc7feec7644e4fb0cca1c6017c16c01d527597c07d86e56963753487ad5497a9630fcc5cf30630ffbc62def116818caf1e345764284dee054959c429e07677d0997c78d0f0ad9190932521cc24d17a2da7d3c3d8108907f2a8835e6a90832a9428198c2552abca4e428d11b7eff5a661fe78d704042743fc65293eb04d35cf150e00b4b2ee9e08690b13c2454caa5f62ee989a0f70449c39701143fde686a13b82225654c2
#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include("compat.inc");

if (description)
{
 script_id(15873);
 script_version("1.26");
 script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/01");

 script_xref(name:"OWASP", value:"OWASP-AUTHN-004");
 script_xref(name:"OWASP", value:"OWASP-AUTHN-006");
 script_xref(name:"OWASP", value:"OWASP-AUTHN-010");

 script_name(english:"Hydra: HTTP");
 script_summary(english:"Brute force HTTP authentication with Hydra.");
 
 script_set_attribute(attribute:"synopsis", value:
"It may be possible to determine HTTP passwords through brute force.");
 script_set_attribute(attribute:"description", value:
"This plugin runs Hydra to find HTTP passwords by brute force. 

To use this plugin, enter the 'Logins file' and the 'Passwords file'
under the 'Hydra (NASL wrappers options)' advanced settings block.");
 script_set_attribute(attribute:"solution", value:
"Change the passwords for the affected accounts.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_attribute(attribute:"cvss_score_source", value:"manual");
 script_set_attribute(attribute:"cvss_score_rationale", value:"No CVE available for this vulnerability.");

 script_set_attribute(attribute:"plugin_publication_date", value:"2004/12/01");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_set_attribute(attribute:"thorough_tests", value:"true");
 script_end_attributes();
 
 script_add_preference(name: "Web page :", value: "", type: "entry");

 script_category(ACT_MIXED_ATTACK);
 script_family(english:"Brute force attacks");

 script_copyright(english:"This script is Copyright (C) 2004-2023 Tenable Network Security, Inc.");

 script_dependencies("webmirror.nasl", "hydra_options.nasl", "find_service1.nasl", "doublecheck_std_services.nasl");
 script_require_keys("Secret/hydra/logins_file", "Secret/hydra/passwords_file", "/tmp/hydra/force_run");
 script_require_ports("Services/www");

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
include("http.inc");

force = get_kb_item("/tmp/hydra/force_run");
if (! force) exit(0, "Neither 'thorough_tests' nor 'force_run' is set.");

logins = get_kb_item("Secret/hydra/logins_file");
if (isnull(logins)) exit(0, "No Hydra logins file.");

port = get_http_port(default:port);

res = http_send_recv3(port         : port,
                      method       : "GET",
                      item         : "/",
                      exit_on_fail : TRUE);

if (res[0] !~ '^HTTP/1\\.[0-9] +[0-9][0-9][0-9]')
  exit(0, "The banner from the HTTP server listening on port "+port+" does not have an HTTP response code.");

timeout = int(get_kb_item("/tmp/hydra/timeout"));
tasks = int(get_kb_item("/tmp/hydra/tasks"));

empty = get_kb_item("/tmp/hydra/empty_password");
login_pass = get_kb_item("/tmp/hydra/login_password");
exit_asap = get_kb_item("/tmp/hydra/exit_ASAP");
tr = get_kb_item("Transports/TCP/"+port);

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
}
else if (! s)
 exit(0, "No Hydra passwords file.");

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
if ( tr >= ENCAPS_SSLv2 )
{
  if (get_kb_item("/tmp/hydra/service/https-get")) svc = "https-get";
  else if (get_kb_item("Hydra/services")) exit(1, "The installed version of Hydra does not support the 'https-get' service.");
  else exit(1, "Failed to get the list of services that the installed version of Hydra supports.");
}
else
{
  if (get_kb_item("/tmp/hydra/service/http-get")) svc = "http-get";
  else if (get_kb_item("Hydra/services")) exit(1, "The installed version of Hydra does not support the 'http-get' service.");
  else exit(1, "Failed to get the list of services that the installed version of Hydra supports.");
}
argv[i++] = svc;

opt = script_get_preference("Web page :");

test_urls = make_list();

if (opt)
  test_urls = make_list(test_urls, opt);  

if(!opt || thorough_tests) 
  v = get_kb_list('www/'+port+'/content/auth_required');

if(!opt && isnull(v))
  exit(0, "No HTTP protected page was found on port "+port+".");

foreach var url (v)
{
  if(!thorough_tests && max_index(test_urls) > 0) break;
  test_urls = make_list(test_urls, url);
}

opt = branch(test_urls);

res = http_send_recv3(port         : port,
                      method       : "GET",
                      item         : opt,
                      exit_on_fail : TRUE);

if (res[0] !~ '^HTTP/1\\.[01] +40[13]' ||
    'www-authenticate' >!<  tolower(res[1]))
  exit(0, "The page "+opt+" on port "+port+" is not protected by HTTP authentication.");
#
argv[i++] = opt;

set_kb_item(name:"Hydra/http/"+port+"/cmd_line", value:join(argv));

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
    report = '\n  Path     : ' + opt + 
             '\n  Username : ' + l + 
             '\n  Password : ' + p + '\n'; 
    set_kb_item(name: 'Hydra/http/'+port, value: l + '\t' + p);
  }
  else if (line =~ "^(Error: |Sorry, hydra)")
  {
    errors = make_list(errors, line);
  }
}

if (report) security_hole(port:port, extra:'\nHydra discovered the following HTTP credentials :\n' + report);

if (max_index(errors) > 0)
{
  msg = '';
  n = 0;
  foreach var error (list_uniq(errors))
  {
    n++;
    if (n < 20) msg = msg + error + '\n';
  }

  set_kb_item(name:"Hydra/errors/http/"+port, value:n);
  set_kb_item(name:"Hydra/error_msg/http/"+port, value:msg);

  exit(1, "One or more errors occurred while running Hydra against the web server listening on port "+port+".");
}

if (!report) exit(0, "Hydra did not discover any credentials for the web server listening on port "+port+".");
