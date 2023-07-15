#TRUSTED 13dbb9c758d29c21eb1f9a5de95e507b90462b8420f37ab9c498f8d721e715252698a7e24bf064390cec0d7ddb6726d41c3dc8810525ee1b604fc7d3cb9c166003652ce2fc335d776111c6ce43d0c4785a5b9f34c35d440090435fe66c30cebdc876ceae8d8b7cfa248c2872f13dfbed8ca5ade4e8115c28460527cb45dec33ae6d43b591ff9267a3f833ab68094c06eb5e75d61bca747d8fdf2e36a764f7e46e412ff65e5941529952308a2d552613e69c7ef231683153b647d75491f388b90b543e55c5775ba25a8e41ca80b97260a611e53400736104ab6d88f702d4372fd314fb7a610827db8467e8b2e2e6bc0036e7fc1c0ba7548e751d5d751e7bcf1ed45b89781253301ad3603ec43d6192738f02a452a439958c69a8b42d6bda5117272ff11d0db098261d7fab1f46814267f3a8e110279cbd888bb105053a88ff1aa248a48265e0f8ff031b764232a39a1423c58f733383f770ae039a2d9d223b183623df0159620a45153f1dac1229a0ff587b5e009af46ec452f0b5ff9a0a56caf1af96e496a8987db8d7e524efd541860b709b9f12d16c24eafbd57e1b3741da38f699564edb8a54e4401862133e911f3febaea1fa23b90d28cc595150de6bc45fbab9ada5fec96fcced07d187fbe821f304066b958a355295dc14c368d12d6cfdf4bb6f8092169f46c8dd007bf36d8089b9069a5c182b455cc34cb419a502b03
#TRUST-RSA-SHA256 07a94500829981c1fd48e260f86384aba50271f193e2f6c93b43b69c0e2ca5149f820aa90d887123dd87ee0efb23a03453d37058cedb9becae7c694c0a0745661b48e5a3ba4b7f75bb1328948370793e1091ab36aa7b1ecc42df6299361225b9e65c74e84ab0155196b1aed52613c78bcb3dcd54683575768c31b5f14386d32b6d40f0df70d6408ec2267f88ed280a70c9f905c634552bbaf789613c94dd621bd1be1e4311cb972e30d17f733528bcfb710453d71a13fff663b8e17d4c62e12a91864677a935f381432337b79cad4238088e7256e192db5049c853604f1bce7afc4556c3b77976b49ff250ffe17bab4ed438b08aa7bbbaf04326556a008396bf5c39c45bf19bdc126c1d29265b6677abb68c45ee959046e53d910b16d521f0bd53fbd9fe01b70f55fdbb9cf8e18860e4e836e1214cc28acff7c6dfa67e0d9934b57ef7e37c8203178a486338aff532450623bb199a552d329516014a5678c460a64cc20515a89a36c96cc5f4cda33a7722cd32015c8782a5f92a853adbb507c341167913c62714fa4c8658ae939b833c6d9b60179839b493d8cadf56de3b2e21ea4416d3c7a8947e5a24914627ec1c57d1b57356ee37c29feeb53685f42c0aac3d9ebdcb380c63967759029e28695738526f296bbc8242e36fe70cbbd1c4446099e69f61ab6038aa39cfadaefa37522e9260e739dc39f0b05dfa95b9328022bb
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(110267);
  script_version("1.19");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/24");
  script_xref(name:"IAVT", value:"0001-T-0536");

  script_name(english:"Apache Zookeeper Server Detection");

  script_set_attribute(attribute:"synopsis", value:
"An Apache Zookeeper server is listening on the remote host.");
  script_set_attribute(attribute:"description", value:
"The remote host is running an Apache Zookeeper server.");
  script_set_attribute(attribute:"see_also", value:"https://zookeeper.apache.org/");
  script_set_attribute(attribute:"solution", value:
"n/a");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2018/05/31");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"asset_inventory", value:"True");
  script_set_attribute(attribute:"asset_inventory_category", value:"software_enumeration");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apache:zookeeper");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Service detection");

  script_copyright(english:"This script is Copyright (C) 2018-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("find_service2.nasl", "process_on_port.nasl", "ssh_get_info.nasl");
  script_require_ports("Services/unknown", 2181);

  exit(0);
}

include('ssh_func.inc');
include('telnet_func.inc');
include('lists.inc');
include('install_func.inc');
include('debug.inc');
include('local_detection_nix.inc');

service_name = "Apache Zookeeper";
protocol = "zookeeper";

ports = make_list(2181);

if (thorough_tests && !get_kb_item("global_settings/disable_service_discovery"))
{
  additional_ports = get_kb_list("Services/unknown");
  if (!isnull(additional_ports))
    ports = make_list(ports, additional_ports);
}

ports = list_uniq(ports);
port = branch(ports);

if (!get_port_state(port))
  audit(AUDIT_PORT_CLOSED, port);

if (get_kb_item('debug_TESTING') == 1)
  response = 'Zookeeper version: 3.1.0,';
else
{
  socket = open_sock_tcp(port);
  if (!socket)
    audit(AUDIT_SOCK_FAIL, port);

  send(socket:socket, data:"stat");
  response = recv(socket:socket, length:2048);
  close(socket);
}
if (empty_or_null(response))
  audit(AUDIT_NOT_DETECT, service_name, port);

match = pregmatch(pattern:"Zookeeper version: ([0-9.]+)[-,]", string:response);
if (empty_or_null(match) || empty_or_null(match[1]))
  audit(AUDIT_NOT_DETECT, service_name, port);

dbg::log(msg:'stat match: ' + obj_rep(match));

version = match[1];

register_service(port:port, ipproto:"tcp", proto:"zookeeper");
replace_kb_item(name:"zookeeper/" + port + "/version", value:version);

if(sshlib::get_support_level() >= sshlib::SSH_LIB_SUPPORTS_COMMANDS ||
    get_one_kb_item('HostLevelChecks/proto') == 'local')
  enable_ssh_wrappers();
else
  disable_ssh_wrappers();

uname = get_kb_item("Host/uname");
proto = get_kb_item("HostLevelChecks/proto");
cmdline = base64_decode(str:get_kb_item("Host/Listeners/tcp/"+port+"/cmdline"));

if (('Linux' >< uname || 'AIX' >< uname) && proto && cmdline)
{
  dbg::log(msg:'Going to try to open ssh connection on port: ' + port);
  if (proto == 'local')
  {
    info_t = INFO_LOCAL;
  }
  else if (proto == 'ssh')
  {
    sock_g = ssh_open_connection();
    if (sock_g) info_t = INFO_SSH;
  }
  if (info_t)
  {
    dbg::log(msg:'ssh connection opened on port: ' + port);
    dbg::log(msg:'cmdline: ' + cmdline);
    match = pregmatch(pattern:"(?<=-cp\x00)([^\x00]+)", string:cmdline);
    if(match && match[1])
    {
      class_paths = split(match[1], sep:':', keep:FALSE);
      dbg::log(msg:'class_paths: ' + obj_rep(class_paths));
      match = collib::filter(f:function ()
          {return _FCT_ANON_ARGS[0] =~ "/.*?zookeeper[^/]*\.jar$";}, class_paths);
      dbg::log(msg:'match after filter: ' + obj_rep(match));
      if (match && max_index(match) == 1)
      {
        jar_path = dirname(match[0]);
        dbg::log(msg:'jar_path: ' + obj_rep(jar_path));
        template = 'cd \"$1$\" && pwd';
        res = ldnix::run_cmd_template_wrapper(template:template, args:[jar_path]);
        dbg::log(msg:'res: ' + obj_rep(res));
        if (res)
          jar_path = res;
      }
    }
    conf_path = pregmatch(pattern:"([^\x00]+?zoo\.cfg)",string:cmdline);
    if (conf_path && conf_path[1])
    {
      dbg::log(msg:'conf_path: ' + obj_rep(conf_path));
      template = 'cat \"$1$\"';
      res = ldnix::run_cmd_template_wrapper(template:template, args:[conf_path[1]]);
    }
    dbg::log(msg:'res from conf_path: ' + obj_rep(res));
    if (res)
    {
      match = pregmatch(pattern:"(?m)^\s*?clientPort=([0-9]+)", string:res, icase:TRUE);
      if (match && match[1] && match[1] == port)
      {
        dbg::log(msg:'match of clientPort: ' + obj_rep(match));
        config = res;
      }
    }
  }

  if (sock_g)
    ssh_close_connection();
}

if (jar_path && config)
{
  register_install(
    vendor:"Apache",
    product:"Zookeeper",
    app_name:service_name,
    port:port,
    path:jar_path,
    version:version,
    extra_no_report:{'config': config},
    cpe: "cpe:/a:apache:zookeeper"
  );
  report_installs(app_name:service_name);
}
else
{
  info = '\n  Version : ' + version + '\n';
  security_report_v4(severity:SECURITY_NOTE, port:port, extra:info);
}
