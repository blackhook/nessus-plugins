#TRUSTED 7eeb0de65fa73f1fe4496cc042f134b89804245ea58d294f49277f0d3b1bf1bee47329d023066ebe03358a41e613eb7d0d359fabc09e4d80ce28ed1b5d6240cbed389caa3bb0b01020bc8ebae334f2a1450b3e0428305be0959ddfe212a1f434d9a6b8401574790a0ef34b4ed0abb33a1a8d8fc232415cbb98e592afc898cadec8c66ba636d96530edcd7533c3423c1c1131e2e59906c4dd15b587ca1f06bb1a43ac2ea65d338e550dc8cabe08891dded461d6c1c389def92a5fa5d078566c8b6f9cc331cd14fd7b76f448b3d11ce8df104d126f3b4774e7d1f1f8dd64587b83d9ad301e768a035fbd6589b9212b91684dbec27217b2c6cb532d4d6595950691c1c9bca43355c6c392dc47c852422fd1e931d7bcfd958c1ad5e87a9ba9344967415f4ce55025beb9ccd880ea1151c4964fd18efa6c71242c0de0d4c457e4b389bb99b92c89cf85383a6f24c08b0f7fd710f0885bbed8941c023cb325c640aeca9c048e785341bd4afc64f7033c007f8c0077b76050ecd4c79a126b140115184c1918245eb9863b87822c86046e59aac9d38169d0440994d027fafd3b88cfa4097eae0d664531ac808e9d880587cfe664792a3ec474078ae640a4db894a1346b53d0d0d97e5afbd4426b46df37bfc8f2ee837471c4c2d52a8787415859418650d92b091dc51af2747598a3120c507dc287d058cb4ff0a03d0c6307294ef5882f4
#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
#

# @PREFERENCES@

include('deprecated_nasl_level.inc');
include("compat.inc");

if (description)
{
  script_id(140575);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/07/26");

  script_name(english:"DTLS Service Detection");

  script_set_attribute(attribute:"synopsis", value:
"The remote service(s) support the DTLS protocol.");
  script_set_attribute(attribute:"description", value:
"Nessus was able to detect that the remote service supports DTLS
 (Datagram Transport Layer Security) by sending a ClientHello and
 receiving a HelloVerifyRequest reply.");
  script_set_attribute(attribute:"solution", value:
"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2020/09/14");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Service detection");

  script_copyright(english:"This script is Copyright (C) 2020-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("dont_scan_printers.nasl", "dont_scan_ot.nasl");
  script_timeout(432000);

  exit(0);
}

include("sets.inc");
include("ports.inc");
include("x509_func.inc");
include("dtls_funcs.inc");

if(get_kb_item("global_settings/disable_service_discovery"))
  exit(0, "Service discovery has been disabled.");

var default_dtls_ports = [
    443,   # Cisco/F5 VPN, Citrix Netscaler Gateway
    601,   # Syslog
    853,   # domain-s DNS query-response 
    2221,  # Ethernet IP service
    3391,  # Microsoft Remote Desktop Gateway
    3478,  # STUN
    4433,  # F5 Network Access Virtual Server
    4740,  # ipfix over DTLS
    4755,  # GRE-in-UDP
    5061,  # SIP
    5246,  # CAPWAP control
    5247,  # CAPWAP data
    5349,  # STUN
    5684,  # COAP - Constrained Application Protocol
    5868,  # Diameter
    6514,  # Syslog over DTLS
    8232,  # HNCP
    10161, # snmpdtls
    10162, # snmpdtls-trap
];

var dtls_version = [DTLS_10, DTLS_12];
var dtls_names = make_array(DTLS_10, "DTLS 1.0", DTLS_12, "DTLS 1.2");
var reported = FALSE;
var num_tested = 0;
var exts;
var dtls_ports = [];
var udp_ports = [];
var port;

function report_finding(port, ver, encaps)
{
  reported = TRUE;
  var desc = "A " + dtls_names[ver] + " server is running on this port.";

  if(service_is_unknown(port:port, ipproto:"udp"))
    set_kb_item(name:"Services/unknown", value:port);

  replace_kb_item(name:"Transports/UDP/" + port, value:encaps);
  replace_kb_item(name:"DTLS/Supported", value:TRUE);

  set_kb_item(name:"Transport/DTLS", value:port);
  set_kb_item(name:"DTLS/Transport/" + port, value:encaps);

  security_note(port:port, protocol:"udp", extra:desc);
}

var testing_pref = get_preference("Test DTLS based services");

#Changed preference name to support .nessus policy import, but policies using the old
#name are still out there.
if(isnull(testing_pref))
{
  dbg::detailed_log(lvl:2, src:FUNCTION_NAME, msg:"New DTLS preference returned NULL.  Trying legacy preference.");
  testing_pref = get_preference("Service Detection[radio]:Test DTLS based services");
}

dbg::detailed_log(lvl:1, src:FUNCTION_NAME, msg:"Using DTLS scan preference: " + testing_pref);

if(isnull(testing_pref) || ('All' >!< testing_pref && 'Known DTLS ports' >!< testing_pref))
  exit(0, "DTLS service discovery has been disabled by scan preference.");

# Negotiate EC-based cipher suites if the Nessus engine supports
# certain ECC operations.
if('All' >< testing_pref)
{
  var base_key = "Ports/udp/";
  var port_list = get_kb_list(base_key + "*");

  if(!isnull(port_list))
  {
    foreach port (keys(port_list))
    {
      port = port - base_key;
      append_element(var:udp_ports, value:port);
    }
  }

  p_set = new("collib::set", default_dtls_ports, udp_ports);
  dtls_ports = p_set.to_list();
}
else if('Known DTLS ports' >< testing_pref)
{
  dtls_ports = default_dtls_ports;
}

DISCOVERY_TIMEOUT = 2;
if(thorough_tests)
  DISCOVERY_TIMEOUT = 6;

var rec, server_hello, ver, encaps, res, dtls_suites;
foreach port(dtls_ports)
{
  num_tested++;

  foreach ver(dtls_version)
  {
    if(ver == DTLS_10)
    {
      encaps = ENCAPS_TLSv1_1;
      dtls_suites = dtls10_ciphers;
    }
    else if(ver == DTLS_12)
    {
      encaps = ENCAPS_TLSv1_2;
      dtls_suites = dtls12_ciphers;
    }
    else
      encaps = ENCAPS_IP;

    var soc = open_sock_udp(port);
    if(!soc)
    {
      dbg::detailed_log(lvl:1, src:SCRIPT_NAME, msg:'failed to open socket on port ' + serialize(port) + ' for DTLS.');
      continue;
    }

    if (!socket_ready(soc))
    {
      dbg::detailed_log(lvl:1, src:SCRIPT_NAME, msg:'socket on port ' + serialize(port) + ' is not ready.');
      close(soc);
      continue;
    }

    # Supported EC curves.
    if (ecc_functions_available())
      exts = tls_ext_ec(keys(curve_nid.tls));

    var dtls = new("dtls", soc, port);
    dtls.set_version(ver);
    res = dtls.init(suites:dtls_suites, exts:exts, timeout:DISCOVERY_TIMEOUT);
    if(!res)
      continue;

    var hfrags = [];
    clt_random = dec2hex(num:unixtime()) + rand_str(length:28);

    rec = dtls.do_client_hello(hfrags:hfrags, clt_random:clt_random);

    if(rec)
    {
      # Process ServerHello
      server_hello = ssl_find(
          blob:rec,
          'content_type', SSL3_CONTENT_TYPE_HANDSHAKE,
          'handshake_type', SSL3_HANDSHAKE_TYPE_SERVER_HELLO
      );

      if(server_hello['version'] == ver)
        report_finding(port:port, ver:ver, encaps:encaps);

      #Send a PROTOCOL VERSION alert here to tell the server we will disconnect
      dtls.send_alert(alert_msg: SSL3_ALERT_TYPE_PROTOCOL_VERSION, alert_level: SSL3_ALERT_TYPE_FATAL);
    }

    #Explicitly destroy the DTLS object out of abundance of caution
    dtls = NULL;
  }
}

if(!reported)
  exit(0, "Tested " + num_tested + " ports.  No DTLS services found.");
