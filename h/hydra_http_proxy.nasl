#TRUSTED 426f67ae105a52af367f4d048871dcd056c8075a7f9ef69f46a08a81a5957d89cb8a04c3085223a6bd6a3d6b38d49a233cbfe620034268cc290d32588ffb4f67d8cd4bdcc31c03b75616f9b41f0a94a6aa6fd353d32b9b06120fb6ca8fc3f19bbda6deaf52b9495b1edc1b00ac35e06bba1c8427f9a59a264c95749c07f7a7b7b3c534fdfc01e54abf03fcb7747e3dbdf7ac36d15af260bfa662c3d32ff4860984ad1b60f9b21e9d02aea64afa91d2d4d11b5209e3f81da60e991c3676fb9f7a412cc0054beb50da9b3a894849a923c45ad3bced947ce61f81ab484d7526f7da81d377d13857f9e69d869121f76082339939eaa8037e7473f202a8c9afe726d7979a11efe4d402d7693c8690525fa589e7def92a99bcbc1c926db79ada31b8022e4569179e893a62fd73ded2f950a2d6d4da969b8efc15974e3c76e9d4c5d95022fd21d33972b8a6b17032812ed38db807d00f533e7960ecbb95ded77a0e896bf91310c9755a7cd40befa98e6b3d4bcdd5d274928620c24b39c2021ba57fa484635294d13208ece22ed32c95e278e11e898af348e6ef1281437d596f866cb39b92d91061fc1e49fa8dab38fdaf58ae25e752e49d2620aa4c1768d66a771c5cf80a0c4ef9ef11fe51e8ef4e0019861277b00319c219078f5e9ab70db3e118406ded4aeb063e20468187dd5d0a658af4fe6be0d9358bb27e4b797b4ca5150ba014
#TRUST-RSA-SHA256 93a6fb3b0f44674032233268186052b8afe7e7a344735c977194b8809f51017b87146c0d1b7c481cfd209b1eb044c96e6eb522047b75944c5e131244249c3a8ab2ca35ee9a5838108293fc13d13905696e4dddd661bad0241a6def2d462f086f640a8bb8a7655718866470a706f31cf84e5ea9addab4dbb1ef26749995605593f5e636080b013868d2a76a4a26b1b576fbd331b2c34bcf66ee02688169e1c8ac261202ab138a1544eb25b9199850c95c2e272d2d3c035a1ee639218f995b33967114be350be90635dd5aa4971e7e383404de86bbdb753eb519a77ad2ecb5490c4ce78e960667273bfff49447f4c1488b3df430638c7ebbaec304332fb621d672d435eac81ff82f053d7bba968f36c54d75a532cbce96747f13aaf4f6a2073d16ec1b81d0ea411581beb66489bba550c2b164cdeb41687047c9dbeb0406a595806d5c306384b793c19492cdb5a92397911b6a0d493b5404ad18f41ffc939d10eda220ed2ae83f8e9bf262de2ce77409f990af93924fdc9af06aeeffe892a0f470bd05e1d5a1e5a90946300a3883a81698ed892b669517e3d570aabd3e314d87bdd3ad53318cbe28d1619ef393c8211bdbc83e6c0a1ccbefcfc151412648c6811ea8c03e2861e876a43abea5107298f4578b65ef0f4b0ed47fa18062b32bfe24c667a9030ca162414c9b94cd9fed55560d9cda21d4a539b53a39d56f6c94712404
#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include("compat.inc");

if (description)
{
 script_id(15874);
 script_version("1.20");
 script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/01");

 script_name(english:"Hydra: HTTP proxy");
 script_summary(english:"Brute force HTTP proxy authentication with Hydra");
 
 script_set_attribute(attribute:"synopsis", value:
"It may be possible to determine HTTP proxy passwords through brute
force.");
 script_set_attribute(attribute:"description", value:
"This plugin runs Hydra to find HTTP proxy accounts and passwords by
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
 
 script_add_preference(name: "Web site (optional) :", value: "", type: "entry");

 script_category(ACT_MIXED_ATTACK);
 script_copyright(english:"This script is Copyright (C) 2004-2023 Tenable Network Security, Inc.");
 script_family(english:"Brute force attacks");

 script_dependencies("hydra_options.nasl", "find_service1.nasl", "doublecheck_std_services.nasl");
 script_require_keys("Secret/hydra/logins_file", "Secret/hydra/passwords_file", "/tmp/hydra/force_run");
 script_require_ports("Services/http_proxy");
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

port = get_service(svc:"http_proxy", exit_on_fail:TRUE);    # port = 3128?

# www.suse.com by default
opt = script_get_preference("Site (optional) :");
if (!opt) site = 'http://www.suse.com/';
else if (opt !~ '^(http|ftp)://') site = strcat('http://', opt);
else site = opt;
host = ereg_replace(string: site, pattern: '^(ftp|http://)([^/]+@)?([^/]+)/.*',
	replace: "\3");
if (host == site)
 req = 'GET '+site+' HTTP/1.0\r\n\r\n';
else
 req = 'GET '+site+' HTTP/1.1\r\nHost: '+host+'\r\n\r\n';
soc = open_sock_tcp(port);
if (!soc) audit(AUDIT_SOCK_FAIL, port);

send(socket: soc, data: req);
r = recv_line(socket: soc, length: 1024);
close(soc);
if (r =~ "^HTTP/1\.[01] +[234]0[0-9] ") exit(0, "The HTTP proxy listening on port "+port+" is not protected.");

timeout = get_kb_item("/tmp/hydra/timeout"); timeout = int(timeout);
tasks = get_kb_item("/tmp/hydra/tasks"); task = int(tasks);

empty = get_kb_item("/tmp/hydra/empty_password");
login_pass = get_kb_item("/tmp/hydra/login_password");
exit_asap = get_kb_item("/tmp/hydra/exit_ASAP");
tr = get_kb_item("Transports/TCP/"+port);

if (get_kb_item("/tmp/hydra/service/http-proxy")) svc = "http-proxy";
else if (get_kb_item("Hydra/services")) exit(1, "The installed version of Hydra does not support the 'http-proxy' service.");
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

if (opt) argv[i++] = opt;

set_kb_item(name:"Hydra/http_proxy/"+port+"/cmd_line", value:join(argv));

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
    report = strcat(report, 'username: ', l, '\tpassword: ', p, '\n');
    set_kb_item(name: 'Hydra/http_proxy/'+port, value: l + '\t' + p);
  }
  else if (line =~ "^(Error: |Sorry, hydra)")
  {
    errors = make_list(errors, line);
  }
}

if (report) security_hole(port:port, extra:'\nHydra discovered the following HTTP proxy credentials :\n\n' + report);

if (max_index(errors) > 0)
{
  msg = '';
  n = 0;
  foreach var error (list_uniq(errors))
  {
    n++;
    if (n < 20) msg = strcat(msg, error, '\n');
  }

  set_kb_item(name:"Hydra/errors/hydra_proxy/"+port, value:n);
  set_kb_item(name:"Hydra/error_msg/hydra_proxy/"+port, value:msg);

  exit(1, "One or more errors occurred while running Hydra against the HTTP proxy server listening on port "+port+".");
}

if (!report) exit(0, "Hydra did not discover any credentials for the HTTP proxy server listening on port "+port+".");
