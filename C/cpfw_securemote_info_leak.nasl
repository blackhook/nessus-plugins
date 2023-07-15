#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(58409);
  script_version("1.7");
  script_cvs_date("Date: 2018/08/17 16:52:59");

  script_bugtraq_id(52430);

  script_name(english:"Check Point SecuRemote Hostname Information Disclosure");
  script_summary(english:"Tries to get hostname");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote host may have an information leak."
  );
  script_set_attribute(
    attribute:"description",
    value:
"Sending a query to the Check Point SecuRemote service can be used to
obtain the hostnames of the firewall and the logging or management
station.  In some environments this may be considered sensitive
information that an attacker could obtain and use to mount further
attacks."
  );
  # http://www.osisecurity.com.au/advisories/checkpoint-firewall-securemote-hostname-information-disclosure
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ec13da59");
  # https://supportcenter.checkpoint.com/supportcenter/portal?eventSubmit_doGoviewsolutiondetails=&solutionid=sk69360
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f4dd7eff");
  script_set_attribute(
    attribute:"solution",
    value:"n/a"
  );
  script_set_attribute(attribute:"risk_factor",value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2012/03/21");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:checkpoint:firewall-1");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:checkpoint:vpn-1");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Firewalls");

  script_copyright(english:"This script is Copyright (C) 2007-2018 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("find_service2.nasl");
  script_require_ports("Services/cpfw1", "Services/fw1_generic", 256, 264);

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("byte_func.inc");

ports = make_list(256, 264);

kblist = get_kb_list('Services/cpfw1');
foreach port (kblist)
  ports = add_port_in_list(list:ports, port:port);

kblist = get_kb_list('Services/fw1_generic');
foreach port (kblist)
  ports = add_port_in_list(list:ports, port:port);

success = FALSE;

foreach port (ports)
{
  if (!get_port_state(port))
  {
    debug_print('Port ' + port + ' is not open.');
    continue;
  }

  soc = open_sock_tcp(port);
  if (!soc)
  {
    debug_print("Failed to open a socket on port "+port+".");
    continue;
  }

  req = '\x51\x00\x00\x00\x00\x00\x00\x21';
  send(socket:soc, data:req);
  res = recv(socket:soc, length:4);

  if (res != 'Y\x00\x00\x00')
  {
    close(soc);
    debug_print('Unexpected response received on port ' + port);
    continue;
  }

  req = '\x00\x00\x00\x0bsecuremote\x00';
  send(socket:soc, data:req);
  len = recv(socket:soc, length:4);

  if (strlen(len) != 4)
  {
    close(soc);
    debug_print('Unexpected length received from port ' + port);
    continue;
  }

  len = getdword(blob:len, pos:0);
  res = recv(socket:soc, length:len);
  close(soc);

  if (strlen(res) != len)
  {
    debug_print('Unexpected response received from port ' + port);
    continue;
  }

  match = eregmatch(string:res, pattern:'^cn=([^,]+),o=([^.]+)\\.', icase:TRUE);
  if (!isnull(match))
  {
    success = TRUE;

    if (service_is_unknown(port:port))
      register_service(port:port, proto:'cpfw1');

    if (report_verbosity > 0)
    {
      report =
        '\n  Firewall host    : ' + match[1] +
        '\n  SmartCenter host : ' + match[2] + '\n';
      security_note(port:port, extra:report);
    }
    else security_note(port);
  }
}

if (!success) exit(0, 'The host is not affected.');
