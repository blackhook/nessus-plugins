#TRUSTED 4432a0d33424ae8730890bc463ece5b5a42d540874f98fe40df635e07fecfb1aafc375c206f05289449b7c6dd4bb2c159289fc7a84956f1d45b99e715556e9d082756586795995d34e9eae3be2da8277b02eea53a0711c9aa14ba32763364efcb77fc2ab4261e71510a0bd08d3ce5376c5be7ac436930f186d8dd270f21baa457e3a18116997930cdced57a148bb2979c1f63e19f632398df8949895c94c74b5dd23ef008f67e12bd5f3d5480160ab38222cb69d13b130dced73bf4dbbc47397c347eec10b006195217c6c024072df22d578d4ba52fc615d51d474db430df9d3cea27a6bb1c61568febf08c1919fcf8f6f1a8b63a995308470052f2e8800581ca97e636c85a8394857d7a81b2934f385a42dc3ac582f0f503beb1bf67ef9835566fb5a958e1a1f9c99d3a3646ee4b2d27e22520d02fdf7b0c9f2c91e79a92f16a11325999528bb6510ccfc3988687b7edb1d5c634891aa96f878e4d0eeb8de5f829e1ded39b45a98988f765bebea87208554f2aa00c581ffa0e88f9ffb65975054dd83d0ed80e4ce342051fc48598c289363e4fd319320e719bdf833f57ebfd299e275ca18152a98a8339ea495e5f18d63c72b413abde64d1c64127fb1689e26d8b1e4da266904c78551b16da1ad372b7fa2d90e0dee5e39bae6fd51307fce39add2ab7dd24d43848126c32002576379e08908c675f8b4635665d0042e534514
#TRUST-RSA-SHA256 5530329a38929d7329a27514919fa65af812f63bab3d18f2161bcfa42cde755dadd8132bd44c51e12626a6d3211776fd953d3fec41979c3175844cd1f71ad30c0edb5b50df28a554fe6e52d42932c981fd6ba3dd6a498218d5ba0a0bf92a34aa3b77159e7a4fb1cbcdf5ad8e77ebbfc2e7b49300a84696b95393d0d9fc23b1ebd2793abd516f46e178bd4d13f1c4ede3851994bc31f782a11fe54b4e370c3d5a54310fea839168255524f96cd3296ea9b71f505a44c36eb09ce1a00777af016da048db1c3ea9407239b1293a296e823224b34807090b1a9e92a765820349cbc07211bcaff182421bb69e66c8cdb7be89959a18f641e81be4c0e1b85d9e9c6052ce1a72eb9fd59747501aae5b75ec33040df72770b0bb7ba54dccf09b2528b65d6f36609d489285e848bd51467093458eb10f5b4d457dcbb0706058eaa8b5109640e6dfc535a9e1428470b53ab4618fb526058597392c0b72348c8a0d99f7b72adf28b1bd7dc9a5655e477edde1394a91623c47dd0f3cd791e41308bb94e80a77e4cba00d470b98e8e57694aab647ee8ac034a5a338337ca0a1a08b31a942e4842cca8d1d3a7971d31169374fa7fc203f49021c6e5947a03aa65ea2c5a6c6d9399664107b062eb9ec751ee713c9c8545938739462c9cd11a69076db513faadbe4597b067fa722524d3a960c46610aefc513b0c96affcc415b3d583d6ac6ae5549
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(15877);
 script_version("1.20");
 script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/01");

 script_name(english:"Hydra: LDAP");
 script_summary(english:"Brute force LDAP authentication with Hydra");
 
 script_set_attribute(attribute:"synopsis", value:
"It may be possible to determine LDAP accounts through brute force.");
 script_set_attribute(attribute:"description", value:
"This plugin runs Hydra to find LDAP accounts and passwords by brute
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
 
 script_add_preference(name: "DN : ", type: "entry", value: "");

 script_category(ACT_MIXED_ATTACK);
 script_copyright(english:"This script is Copyright (C) 2004-2023 Tenable Network Security, Inc.");
 script_family(english:"Brute force attacks");

 # find_service does not detect LDAP yet, so we rely upon amap
 # However find_services will detect the SSL layer for LDAPS
 script_dependencies("hydra_options.nasl", "find_service1.nasl", "doublecheck_std_services.nasl", "external_svc_ident.nasl", "ldap_detect.nasl");
 script_require_keys("Secret/hydra/logins_file", "Secret/hydra/passwords_file", "/tmp/hydra/force_run");
 script_require_ports("Services/ldap", 389);

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

dn = script_get_preference("DN : ");
if (! dn) exit(0, "No DN provided.");

port = get_service(svc:"ldap", exit_on_fail:TRUE);

# We should check that the server is up & running

timeout = get_kb_item("/tmp/hydra/timeout"); timeout = int(timeout);
tasks = get_kb_item("/tmp/hydra/tasks"); task = int(tasks);

empty = get_kb_item("/tmp/hydra/empty_password");
login_pass = get_kb_item("/tmp/hydra/login_password");
exit_asap = get_kb_item("/tmp/hydra/exit_ASAP");
tr = get_kb_item("Transports/TCP/"+port);

if (get_kb_item("/tmp/hydra/service/ldap")) svc = "ldap";
else if (get_kb_item("Hydra/services")) exit(1, "The installed version of Hydra does not support the 'ldap' service.");
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
argv[i++] = dn;

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
    set_kb_item(name: 'Hydra/ldap/'+port, value: l + '\t' + p);
  }
  else if (line =~ "^(Error: |Sorry, hydra)")
  {
    errors = make_list(errors, line);
  }
}

if (report) security_hole(port:port, extra:'\nHydra discovered the following LDAP credentials :\n\n' + report);

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

  exit(1, "One or more errors occurred while running Hydra against the LDAP server listening on port "+port+".");
}

if (!report) exit(0, "Hydra did not discover any credentials for the LDAP server listening on port "+port+".");
