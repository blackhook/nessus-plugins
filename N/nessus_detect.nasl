#TRUSTED 34c1640d5365fbea50987c7a5deb7e4fb40f05d471e5bf471e765bc5fdeeb83d5a3b76b7c26d574561d9cfac07bab08d84b4371b412c464e0bb81c69de6c643d3915254f0ab53528e4cfcc499c1dbed38c2cb2d91606d6db33a89b9fd3875a4fa259ea8e8f6c1afec1d5017a985d634ce01caa819a916f6649392870350a217857bccd9f4062c2ebd52eefd4b90c2c2853fb80402a3f4bd152db8ffaf3ddb9d4634840af0b53150ad572213580152ec46d873b0111ef3803888c0e535630d98deebafa971c5ebeaca010781ba18eca95b560720e599cd80854dc1fbe4dcb957990c89eb1e557f226a93b52f9b979bc11ad0722b32845cde449997450249b61a2ac8bba89380e63d56e21e738ba24555ac9ddc5906c58eb6ca10f22579003d7e41cb2df01c425fe05a3273614d10fe41bd6287328464d6abb3f30b794e2acd23061fcf722f85af950e216e647e2ca2dac34dea0f8099627126fae380cc9146da848aa5d93ebbb2a0f37c9df739f4aab52fc2ee94c712d6899224b910b1b48c8b35bb7f63c1672ec6cfaff609fd8d2876bdfb724b46e13436b14bc25fe2b7bd2017aa40cc122687147682c5d3ae0e223b477cffbfbe01ced6469738be0361c4025752fe1c4020b59f64cf3a63e24627fbab60643d1dd596ccc188c7eaa9023412ee529f7d2a380deb48885562f3dda74a3bb4fa60f29b3950712edc4f9e2f8bc58
#TRUST-RSA-SHA256 1e54fdcffb7928a3b1bb6acdfec80a1afcab3972dbd101db3c4c1dce728c4f7ee5832fa463412111fda636c2f835413a9b09821ac28d3caf6bf7fdce38ff6b9f076a58b5f40bda58248ecb70856c4db14ec7db871f3b4a47cf80b09833934c00925cea6c46e08b42d1f8c3aa9c649f7680a472af552ed18d6118116903eabd96cf848dfb2fb77bff8af97a086b5b5f485985b4162d4a66c87f7a1f0f7416087305b5ac5df7ec415414ad579ca90261b4515b99ba6635cc18d76c5a4253bd000dfe9f48cd744fc187693be767e16ad59603532c404f4c4133543c5fa7484aab4511925b2231b2823ef6768476dec8e8bb19ea195d81655999e2b78901e8719fbc27b2b8f85f0a8486eb393d5ca6ae9f72e737a6caf9bc8a64f8ca75fc514c9c50fbe83630a4cb3e5c5135849450773db3eb2a506d7cd7f0c87eff7552c94f94c72068b2819640c0a06d160252894e9654784711c72ec06950cb344116ff2ff86424ecf1bbc6255bac95b6102d33d55980e284fa81492669776e29b312372c016851ccda3522911250ecdbc17bde89be5d89b3964566054aa168dc058fbd1c1821e0e6e5a411f719462b5ba358409e52cab35d2d70dfb6a552625767011e8130df8c1371d9508f3da793c45968b9f719f112241f7912953fd35be6ce6d58914b6ce763b65e6a7922f29381512248e4853bd58b9f20be556bf365a0fd07b5782bb2
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(10147);
  script_version("1.56");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/02/08");
  script_xref(name:"IAVT", value:"0001-T-0673");

  script_name(english:"Nessus Server Detection");

  script_set_attribute(attribute:"synopsis", value:
"A Nessus daemon is listening on the remote port.");
  script_set_attribute(attribute:"description", value:
"A Nessus daemon is listening on the remote port.");
  script_set_attribute(attribute:"see_also", value:"https://www.tenable.com/products/nessus/nessus-professional");
  script_set_attribute(attribute:"solution", value:
"Ensure that the remote Nessus installation has been authorized.");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"1999/10/12");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"asset_inventory", value:"True");
  script_set_attribute(attribute:"asset_inventory_category", value:"software_enumeration");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:tenable:nessus");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Service detection");

  script_copyright(english:"This script is Copyright (C) 1999-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("find_service2.nasl", "pvs_proxy_detect.nasl", "http_version.nasl");
  script_require_ports("Services/unknown", 1241, "Services/www", 8834);

  exit(0);
}

include('http.inc');
include('install_func.inc');
include('json.inc');
include('spad_log_func.inc');

var app = 'Tenable Nessus';

function nessus_detect(port)
{
  var soc = open_sock_tcp(port);
  if (soc)
  {
    send(socket:soc, data:'< NTP/1.2 >\n');
    var r = recv_line(socket:soc, length:4096);
    if ( '< NTP/1.2 >' >< r )
    {
      r = recv(socket:soc, length:7);
      close(soc);
      if ( 'User : ' >< r )
      {
        register_service(proto:app, port:port);
        security_note(port);
      }
    }
    else close(soc);
  }
  else
  {
    spad_log(message:'Problem when opening socket at port '+port);
  }
}

function nessus_ntp_detection()
{
  var ntp_port;
  var checks = TRUE;
  if (thorough_tests)
  {
    ntp_port = get_unknown_svc(1241);
    if (!ntp_port)
    {
      checks = FALSE;
      spad_log(message:'Service on port '+ ntp_port+' already known');
    }
    if (silent_service(ntp_port))
    {
      checks = FALSE;
      spad_log(message:'Service on port' + ntp_port+' is silent');
    }
  }
  else ntp_port = 1241;
  if (checks && get_port_state(ntp_port))
  {
    if (known_service(port:ntp_port)) spad_log(message:'Service already known on port ' + ntp_port);
    else nessus_detect(port:ntp_port);
  }
  else spad_log(message:'NTP port '+ntp_port+' closed');
}

# Nessus < 4.2
if (thorough_tests) nessus_ntp_detection();

# Nessus >= 4.2
var port = get_http_port(default:8834, ignore_broken:TRUE);

var install = NULL;
var version = NULL;
var extra   = make_array();
var nasl_version = NULL;
var feed    = NULL;
var web     = NULL;

if (!isnull(port))
{
  var server_header = http_server_header(port:port);
  if ('NessusWWW' >< server_header)
  {
    var res = http_send_recv3(method:'GET', item:'/server/properties', port:port);
    spad_log(message:'Response from GET /server/properties: ' + obj_rep(res));
    if (!isnull(res))
    {
      if ('Nessus' >< res[2])
      {
        # Response body should contain a json string
        var json = json_read(res[2]);

        # Version 5 returns a string with the same hierarchy as the XML on the /feed page
        var data;
        if (res[2] =~ '^{"reply"') data = json[0]['reply']['contents'];
        # Version 6 gets straight to the point
        else data = json[0];

        if (data['nessus_type'] !~ '^Nessus') exit(0, 'Server did not respond with expected Nessus Server properties information.');
        if ('SecurityCenter' >< data['nessus_type']) extra['Managed by'] = 'SecurityCenter';

        feed         = data['feed'];
        version      = data['nessus_ui_version'];
        nasl_version = data['server_version'];
        web          = data['web_server_version'];

        if (!isnull(feed))   extra['Nessus feed'] = feed;
        if (!isnull(web))    extra['Web server version'] = web;
        if (!isnull(nasl_version))     extra['NASL Version'] = nasl_version;
        if (isnull(version) || version == '0.0.0') version = UNKNOWN_VER;

        install = register_install(
          app_name : app,
          vendor : 'Tenable',
          product : 'Nessus',
          version  : version,
          port     : port,
          path     : '/',
          webapp   : TRUE,
          extra    : extra,
          cpe    : 'cpe:/a:tenable:nessus');
      }
      else
      {
        res = NULL;
        res = http_send_recv3(method:'GET', item:'/feed', port:port);
        spad_log(message:'Response from GET /feed: ' + obj_rep(res));
        if (!isnull(res))
        {
          if ('<nessus_type>Nessus' >!< res[2])
            exit(0, 'Server did not respond with expected Nessus Feed information.');

          if ('<feed>' >< res[2])
          {
            feed = strstr(res[2], '<feed>') - '<feed>';
            feed = feed - strstr(feed, '</feed>');
          }

          if ('<server_version>' >< res[2])
          {
            nasl_version = strstr(res[2], '<server_version>') - '<server_version>';
            nasl_version = nasl_version - strstr(nasl_version, '</server_version>');
          }

          if ('<web_server_version>' >< res[2])
          {
            web = strstr(res[2], '<web_server_version>') - '<web_server_version>';
            web = web - strstr(web, '</web_server_version>');
          }

          if ('<nessus_ui_version>' >< res[2])
          {
            version = strstr(res[2], '<nessus_ui_version>') - '<nessus_ui_version>';
            version = version - strstr(version, '</nessus_ui_version>');
          }

          if (!isnull(feed)) extra['Nessus Feed'] = feed;
          if (!isnull(web)) extra['Web Server Version'] = web;
          if (!isnull(nasl_version)) extra['NASL Version'] = nasl_version;

          install = register_install(
            app_name : app,
            vendor : 'Tenable',
            product : 'Nessus',
            version  : version,
            port     : port,
            path     : '/',
            webapp   : TRUE,
            extra    : extra,
            cpe    : 'cpe:/a:tenable:nessus');
        }
        else
        {
          spad_log(message:'Cannot access Nessus feed.');
        }
      }
    }
    else
    {
      spad_log(message:'Cannot access server/properties file.');
    }
  }
  else
  {
    spad_log(message:'Server header does not seem to be NessusWWW.');
  }
}

if (!isnull(install))
{
  report_installs(app_name:app, port:port);
  exit(0);
}
else
{
  # if we reach this point, none of the methods worked
  # given NTP is for legacy Nessus, we report on 
  # the HTTP-based detection
  audit(AUDIT_RESP_BAD, port);
}

