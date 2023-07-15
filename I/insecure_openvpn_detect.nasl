#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include("compat.inc");

if (description)
{
  script_id(107073);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_name(english:"Unauthenticated OpenVPN Server Detection");

  script_set_attribute(attribute:"synopsis", value:
"An unauthenticated OpenVPN server is listening on the remote host.");
  script_set_attribute(attribute:"description", value:
"The remote host is running an OpenVPN server. Based on its responses,
the remote host appears to be in unauthenticated mode. This means that
the tunnel is unencrypted and authentication is disabled.");
  script_set_attribute(attribute:"see_also", value:"https://openvpn.net/");
  script_set_attribute(attribute:"solution", value:
"Enable authentication");
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_publication_date", value:"2018/02/28");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"asset_inventory", value:"True");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:openvpn:openvpn");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Service detection");

  script_copyright(english:"This script is Copyright (C) 2018-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("find_service2.nasl");
  script_require_ports(1194, 5000, "Services/unknown");
  script_timeout(1800);

  exit(0);
}

include("byte_func.inc");
include("global_settings.inc");
include("misc_func.inc");
include("audit.inc");

# port 1194 is the default for 2.x and 5000 is the default for 1.x
port_list = make_list(1194, 5000);

if (thorough_tests && !get_kb_item("global_settings/disable_service_discovery"))
{
  additional_ports = get_kb_list("Services/unknown");
  if (!isnull(additional_ports))
  {
    port_list = make_list(port_list, additional_ports);
  }

  udp_ports = get_kb_list("Ports/udp/*");
  if (!isnull(udp_ports) && get_kb_item("Host/scanners/nessus_udp_scanner"))
  {
    foreach udpport (keys(udp_ports))
    {
      udpport = udpport - "Ports/udp/";
      port_list = make_list(port_list, udpport);
    }
  }
}

# ensure we have no duplicates
port_list = list_uniq(port_list);

# loop over all the ports and try both udp/tcp connects for all
found = FALSE;
foreach port (port_list)
{
  foreach protocol (make_list('udp', 'tcp'))
  {
    soc = NULL;
    if (!service_is_unknown(port:port, ipproto:protocol))
    {
      # we aren't interested in known services
      continue;
    }

    # Send an unencrypted OpenVPN Configuration Control request packet
    # Start with occ magic
    request = '\x28\x7f\x34\x6b\xd4\xef\x7a\x81\x2d\x56\xb8\xd3\xaf\xc5\x45\x9c';
    request += '\x00'; # request

    response = NULL;
    if (protocol == 'udp')
    {
      if (!get_udp_port_state(port))
      {
        continue;
      }
      soc = open_sock_udp(port);

      if (!soc)
      {
        continue;
      }

      send(socket:soc, data:request);
      response = recv(socket:soc, length:1024);
      close(soc);
    }
    else
    {
      if (!get_tcp_port_state(port))
      {
        continue;
      }
      soc = open_sock_tcp(port);

      if (!soc)
      {
        continue;
      }

      # tcp request/responses start with a two byte length
      request = mkword(len(request)) + request;
      send(socket:soc, data:request);

      length = recv(socket:soc, length:2, min:2);
      if (empty_or_null(length))
      {
        close(soc);
        continue;
      }
      length = getword(blob:length, pos:0);
      response = recv(socket:soc, length:int(length), min:int(length));
      close(soc);
    } 

    # Check for an OCC reply and pull out the configuration data
    match = pregmatch(pattern:"\x28\x7f\x34\x6b\xd4\xef\x7a\x81\x2d\x56\xb8\xd3\xaf\xc5\x45\x9c\x01([A-Za-z0-9,\.\-_ ]+)", string:response);
    if (!empty_or_null(match) && "dev-type" >< match[1])
    {
      found = TRUE;
      register_service(port:port, ipproto:protocol, proto:"openvpn");
      set_kb_item(name:"openvpn/" + port, value:TRUE);
      set_kb_item(name:"openvpn/" + port + "/proto", value:protocol);

      report = '\nOpenVPN on ' + protocol + ' port ' + port + ' is running in unauthenticated mode' +
               '\nwith the following config:\n' +
               '\n' +
               match[1] +
               '\n';
      security_report_v4(port:port, proto:protocol, severity:SECURITY_HOLE, extra:report);
    }
  }
}

if (found == FALSE)
{
  audit(AUDIT_NOT_DETECT, "Unauthenticated OpenVPN");
}
