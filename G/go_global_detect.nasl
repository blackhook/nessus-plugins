#
# (C) Tenable Network Security, Inc.
#



include("compat.inc");

if (description) {
  script_id(20177);
  script_version("1.13");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/06/01");

  script_name(english:"GO-Global Server Detection");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is running a remote-display server.");
  script_set_attribute(attribute:"description", value:
"The remote host is running a GO-Global server, a commercial thin-
client computing solution for Windows and unix.");
  # http://web.archive.org/web/20071213222730/http://www.graphon.com/products/index.shtml
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?3e3f3d66");
  script_set_attribute(attribute:"solution", value:
"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2005/11/10");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"asset_inventory", value:"True");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:graphon:go-global");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Service detection");

  script_copyright(english:"This script is Copyright (C) 2005-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_require_ports("Services/unknown", 443, 491);

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");


if (thorough_tests && ! get_kb_item("global_settings/disable_service_discovery")  ) {
  port = get_unknown_svc(491);
  if (!port) exit(0);
  ports = make_list(port);
}
# nb: WebAccess is GO-Global on port 443 rather than 491.
else ports = make_list(443, 491);


foreach port (ports) {
  if (
    get_tcp_port_state(port) && 
    service_is_unknown(port:port)
  ) {
    # Send an initial greeting asking for RSA encryption.
    soc = open_sock_tcp(port);
    if (soc) {
      req = raw_string("_USERSA_");
      send(socket:soc, data:req);

      # Make sure the response looks like it's from a GO-Global server.
      #
      # nb: the initial char indicates the server's OS - "_" => Windows.
      res = recv(socket:soc, length:256);
      if (isnull(res) || "USERSA" >!< res) exit(0);

      # Send a second packet so we avoid catching a quote service.
      req = raw_string(
        0x00, 0x40,                           # constant???
        0xF9, 0x42, 0x88, 0x1C, 0x81, 0x19, 0x68, 0x10, 
        0xF7, 0x39, 0x9A, 0x11, 0xA4, 0xDD, 0x1A, 0xFB, 
        0xD2, 0xFF, 0xC2, 0x35, 0x76, 0xBF, 0x47, 0x5B, 
        0x67, 0xD4, 0xFA, 0x2E, 0xAB, 0x49, 0x4E, 0x3F, 
        0x33, 0x7F, 0x98, 0x01, 0x47, 0x1D, 0x7A, 0x3A, 
        0x6C, 0x6F, 0xBD, 0x89, 0xEC, 0x89, 0xBC, 0x33, 
        0x1D, 0xB7, 0x8E, 0xEE, 0xF6, 0x4D, 0xA4, 0x5B, 
        0x73, 0x47, 0x68, 0x97, 0xD9, 0x39, 0xC6, 0x59, 
        0x00, 0x01, 0x11                      # constant???
      );
      send(socket:soc, data:req);

      # Read the response.
      res = recv(socket:soc, length:256);
      if (isnull(res)) exit(0);
      close(soc);

      # It's a GO-Global server if...
      if (
        # the packet length is 132 bytes and...
        strlen(res) == 132 && 
        # the initial two bytes are 0x0040.
        substr(res, 0, 1) == raw_string(0x00, 0x40)
      ) {
        # Register and report the service.
        register_service(port:port, ipproto:"tcp", proto:"go-global");

        security_note(port);
      }
    }
  }
}
