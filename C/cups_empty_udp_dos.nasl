#%NASL_MIN_LEVEL 70300
#
# This script was written by George A. Theall, <theall@tifaware.com>.
#
# See the Nessus Scripts License for details.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(15900);
  script_version("1.16");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/08/15");

  script_cve_id("CVE-2004-0558");
  script_bugtraq_id(11183);

  script_name(english:"CUPS Internet Printing Protocol (IPP) Implementation Empty UDP Datagram Remote DoS");

  script_set_attribute(attribute:"synopsis", value:
"The remote print server is affected by a denial of service 
vulnerability.");
  script_set_attribute(attribute:"description", value:
"The target is running a CUPS server that supports browsing of network
printers and that is vulnerable to a limited type of denial of service
attack.  Specifically, the browsing feature can be disabled by sending
an empty UDP datagram to the CUPS server.");
  script_set_attribute(attribute:"see_also", value:"http://www.cups.org/str.php?L863");
  script_set_attribute(attribute:"see_also", value:"ftp://ftp.sco.com/pub/openserver5/507/mp/osr507mp4/osr507mp4.htm");
  # ftp://ftp.sco.com/pub/updates/OpenServer/SCOSA-2005.49/SCOSA-2005.49.txt
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0ff4652a");
  script_set_attribute(attribute:"see_also", value:"ftp://ftp.sco.com/pub/updates/UnixWare/SCOSA-2004.15/SCOSA-2004.15.txt");
  script_set_attribute(attribute:"solution", value:
"Upgrade to CUPS 1.1.21rc2 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2004/09/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2004/12/03");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apple:cups");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_DENIAL);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2004-2022 George A. Theall");

  script_dependencies("find_service1.nasl", "global_settings.nasl", "http_version.nasl");
  script_require_keys("www/cups");
  script_require_ports("Services/www", 631);
  script_require_udp_ports(631);

  exit(0);
}

include("global_settings.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");


# This function tries to add a printer using the browsing feature.
#
# Args:
#   o port, CUPS port number (note: both tcp and udp port # are assumed equal)
#   o name, a name for the printer
#   o desc, a description of the printer.
#
# Return:
#   1 if successful, 0 otherwise.
function add_printer(port, name, desc) {
  local_var packet, req, res, soc, url;

  if (! get_udp_port_state(port)) return 0;

  # CUPS Browsing Protocol is detailed at <http://www.cups.org/idd.html#4_2>.
  packet = string(
      "6 ",                             # Type (remote printer w/o colour)
      "3 ",                             # State (idle)
      "ipp://example.com:", port, "/printers/", name, " ",  # URI
      '"n/a" ',                         # Location
      '"', desc, '" ',                  # Information
      '"n/a"'                           # Make and model
  );
  dbg::detailed_log(lvl:2, msg:"debug: sending packet.",
    msg_details:{"Packet":{"lvl":3, "value":packet}});
  soc = open_sock_udp(port);
  # nb: open_sock_udp is unlikely to fail - after all, this is udp.
  if (!soc) return 0;
  send(socket:soc, data:string(packet, "\n"));
  close(soc);

  # Check whether cupsd knows about the printer now.
  url = string("/printers/", name);
  dbg::detailed_log(lvl:2, src:FUNCTION_NAME, msg:"debug: checking '"+url+"'.");
  req = http_get(item:url, port:port);
  res = http_keepalive_send_recv(port:port, data:req);
  if (res == NULL) return(0);           # can't connect
  dbg::detailed_log(lvl:3, src:FUNCTION_NAME, msg:"debug: received",
    msg_details:{"Data":{"lvl":3, "value":res}});
  if (egrep(string:res, pattern:string("Description: ", desc))) return 1;
  return 0;
}


host = get_host_name();
ports = add_port_in_list(list:get_kb_list("Services/www"), port:631);
foreach port (ports) {
  # Look at port only if it corresponds to a CUPS server.
  banner = get_http_banner(port:port);
  if (egrep(string:banner, pattern:"Server: CUPS")) {
    dbg::detailed_log(lvl:2, msg:"debug: checking for empty UDP datagram DoS vulnerability in CUPS on "+host+":"+port+".");

    # NB: since ICMP unreachable are easily dropped by firewalls, we can't
    #     simply probe the UDP port: doing so would risk false positives.
    #     So, we'll try adding a printer using the browsing protocol and
    #     check whether it was indeed added.
    rc = add_printer(port:port, name:"nasl_test1", desc:"NASL Plugin Test #1");

    if (rc == 1) {
      dbg::detailed_log(lvl:2, msg:"debug: browsing works; sending empty datagram.");
      soc = open_sock_udp(port);
      # nb: open_sock_udp is unlikely to fail - after all, this is udp.
      if (!soc) exit(0);
      send(socket:soc, data:"");
      close(soc);
      # NB: if browsing is disabled, cups error log will have lines like:
      #   Oct  6 16:28:18 salt cupsd[26671]: Browse recv failed - No such file or directory.
      #   Oct  6 16:28:18 salt cupsd[26671]: Browsing turned off.

      # Check whether browsing is still enabled.
      dbg::detailed_log(lvl:2, msg:"debug: testing if port is still open.");
      rc = add_printer(port:port, name:"nasl_test2", desc:"NASL Plugin Test #2");
      if (rc == 0) {
        dbg::detailed_log(lvl:2, msg:"debug: looks like the browser was disabled.");
        security_warning(port:port, proto:"udp");
      }
    }
  }
}
