#TRUSTED 0313560a73e5c00ba9dae3083ade93a734809af5506013ec17ecaae5573ca83d829de2f5e3cdada684015271bc783b88e28099d37e2af6c82d2b36f5e1c52d167f345f4010618a42b449637567778ab2427ed5ad40d8e1c9c610e12f03a0ec6843858217c3e3b0e2cc10e9962a5cf94801abd782c34c735278966c621d20f09d0f7bcc98d18888accac855ca5a667984f7f7c015ac06f1bbb9773b7f10e22240f26b45c9e57ee004c74760108c6ddb9e65b7143d9303b9899d8f74282df303a33c1ab958270f40a03be2bf2b58ede15b6bf05a4169bbd6de0092beccb96b2c250dbedd9ddc4be9dc5ac9c7197a113eaf1e5236292cff9bcb64975a262e7b0eebfeeb0f3a4cdfcf540b27a7d6768d648702655982fdcdf3128a8ff7b39cdbb42cb582a88c3fb0dc8f28c65cc44a9a4ad9354e491b01bbb17c85d771d3269d9e7bf13d835fbf8b667b3d96aede93f117748f6c2b54fd5e99317cb5e09de0b1b02a56d27171f942e214a4ea673d9d7e7a90655cb29c1c93bd19b3a9745ce7dee376606f14e8f4c6db6b3a043762993260a4523eb2ddbcc97f6aa16a54a1bd626db49c1666512b6f54a50dffaab4418af25f2333a65000b40cc08f485036c0fba1e34239ae8f941cd8e2330c517522bb165f6d49f2bf89115ac67529806d42d234835dcf426f1c2bca53409ecc54eefed56943936cbeda27da5e31b0f1423aa9b901
#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include("compat.inc");

if (description)
{
  script_id(26026);
  script_version("1.16");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_name(english:"Tor Server Detection");

  script_set_attribute(attribute:"synopsis", value:
"A Tor server is listening on the remote host.");
  script_set_attribute(attribute:"description", value:
"The remote service appears to be a Tor server.  Tor is a proxy service
designed to protect the anonymity of its users.  It can also be used
to support hidden services.");
  script_set_attribute(attribute:"see_also", value:"https://tor.eff.org//");
  script_set_attribute(attribute:"solution", value:
"Make sure use of this program is in accordance with your corporate
security policy.  And limit incoming traffic to this port if desired.");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2007/09/14");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"asset_inventory", value:"True");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:torproject:tor");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Service detection");

  script_copyright(english:"This script is Copyright (C) 2007-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("find_service1.nasl");
  script_require_ports("Services/unknown", 9001);

  exit(0);
}

include("x509_func.inc");

if (thorough_tests && ! get_kb_item("global_settings/disable_service_discovery")  )
{
  var port = get_unknown_svc(9001);
  if (!port) exit(0);
}
else port = 9001;
if (known_service(port:port)) exit(0);
if (!get_tcp_port_state(port)) exit(0);
# TOR servers use TLS1.
if (ENCAPS_TLSv1 == get_kb_item("Transports/TCP/"+port))
{
  # Grab the certificate and validity dates.
  var cert = get_server_cert(port:port, encoding:"der");
  if (isnull(cert)) exit(1, "Failed to get cert from server listening on port "+port+".");

  var v = stridx(cert, raw_string(0x30, 0x1e, 0x17, 0x0d));
  if (v >= 0)
  {
    v += 4;
    var valid_start = substr(cert, v, v+11);
    v += 15;
    var valid_end = substr(cert, v, v+11);
  }

  # If...
  if
  (
    # the certificate's issuer has O=Tor in it and...
    stridx(cert, "U"+mkbyte(0x04)+mkbyte(0x0a)+mkbyte(0x13)+mkbyte(0x03)+"Tor1") >= 0 &&
    # it has " <identity>" in it and...
    " <identity>" >< cert &&
    # the dates look valid and...
    (valid_start =~ "^[0-9]{12}$" && valid_end =~ "^[0-9]{12}$") &&
    # the minutes and seconds are equal and...
    substr(valid_start, 8) == substr(valid_end, 8) &&
    # the certificate is valid only for two hours.
    2 == int(substr(valid_end, 0, 7)) - int(substr(valid_start, 0, 7))
  )
  {
    # Extract some interesting info for the report.
    var info = "";
    # - router name.
    var name = strstr(cert, "Tor1");
    name = name - strstr(name, " <identity>");
    var i = stridx(name, "U"+mkbyte(0x04)+mkbyte(0x03)+mkbyte(0x14));
    if (i >= 0)
    {
      info += "  Router name : " + substr(name, i+5) + '\n';
    }

    # Register and report the service.
    register_service(port:port, proto:"tor");

    var report = "";
    if (!empty_or_null(info))
    {
      report =  'Nessus was able to gather the following information from the remote' +
      report += '\n Tor server :\n';
      report += '\n' + info;

      security_report_v4(port:port, extra:report, severity:SECURITY_NOTE);
    }
    else security_report_v4(port:port, extra:report, severity:SECURITY_NOTE);
  }
}