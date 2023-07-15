#TRUSTED 692f327bf5ca7c1a07670c367a0bc39d845024071edea8fd9f224f91b3cdac95fb98552ca359e7eac7b1081a4edea0b83e4d0266fb1b38e4519d81c5b1473c5bbde15c5e429253d869a224d8bac05ce8c8ea33446ba6526a16c90ed3d72970695d88340cce25e4c1c53b5240c8d65f83af0e02204e3eef97baa93111f2410bbdbfa21dac65bcf2953f6359009da2bf2f0d21253f697fdb16b69ecf3cb6db296ffc771d3fd9b89b92a3a34be5d5ed021f0437549dce57cd482c303ffb089bf3b16fc49e9d899de6031056b8473c8f57cb0c85ba8e9f624cba08dff3e4c8b31c46c3283f53e9788a0287e6fa37df99077daf53a807c47ecb3690433b2305b27249df95c10779a064e90f0757bcc916bd8a50c273a1b3d0fac8fd1b5e40f995bd5ee1a3b68db76a21d1e63aaad1e879586323638c96fbc496e5fbb392c544bcd91c87701f7ed0f87c6020b7a21de3bd9587b65c8acc45e67a4236bf439dbbde92c5c3fd13836f28b8d08df482432536062a7035a2486b359ef353a103ef51ff94c063e7ce01afc1ecf90818b12d5032aa51abcfe3f4fae0f1d7b3d2d158078540c69d06ea9bc6adfd2198c74a6bdfb68fa3f84afd51454d03973edf3f08c1702d21b6997ca5bd917d288d4da515ff30737bda4439d61f4650eab0d8a3ffc3b58790228f7f4c3378544330c7ed4b408956185e423fca4d3b75cb4b7ec19834fce4b4
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(56209);
 script_version("1.32");
 script_set_attribute(attribute:"plugin_modification_date", value:"2020/11/06");

 script_name(english:"PCI DSS Compliance : Remote Access Software Has Been Detected");
 script_summary(english:"Modify global variables for PCI DSS.");

 script_set_attribute(attribute:"synopsis", value:
"Remote access software has been detected.");
 script_set_attribute(attribute:"description", value:
"Due to increased risk to the cardholder data environment when remote
 access software is present, 1) justify the business need for this 
software to the ASV and confirm it is implemented securely, or 2) 
confirm it is disabled/ removed. Consult your ASV if you have
questions about this Special Note.");
 script_set_attribute(attribute:"solution", value:"n/a");

 script_set_attribute(attribute:"plugin_publication_date", value:"2011/09/15");

 script_set_attribute(attribute:"plugin_type", value:"summary");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
 script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L");
 script_set_attribute(attribute:"cvss_score_source", value:"manual");
 script_set_attribute(attribute:"cvss_score_rationale", value:"Score from an in depth analysis done by Tenable");

 script_end_attributes();

 script_category(ACT_END);

 script_copyright(english:"This script is Copyright (C) 2011-2020 and is owned by Tenable, Inc. or an Affiliate thereof.");
 script_family(english:"Policy Compliance");

 script_require_keys("Settings/PCI_DSS");
 script_exclude_keys("Settings/PCI_DSS_local_checks");
 exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("install_func.inc");

if (!get_kb_item("Settings/PCI_DSS")) audit(AUDIT_PCI);
if (get_kb_item("Settings/PCI_DSS_local_checks"))
  exit(1, "This plugin only runs for PCI External scans.");

function pci_webapp_chk(port, app)
{
  if (isnull(app) || isnull(port)) return NULL;
  local_var install, chk_app, dir, urls;

  urls = make_list();
  chk_app = get_installs(
    app_name : app,
    port     : port
  );
  if (chk_app[0] == IF_OK)
  {
    foreach install (chk_app[1])
    {
      dir = install['path'];
      urls = make_list(urls, build_url2(qs:dir, port:port));
    }
    return urls;
  }
  else
    return NULL;
}

str = NULL;

ports = get_kb_list("Services/www");

if ( ! isnull(ports) )
{
 foreach port ( make_list(ports) )
 {
   page = get_kb_item("Cache/" + port + "/URL_/");
   # Cisco
   if ( page && 'WWW-Authenticate: Basic realm="level_15' >< page )
    {
      str += '\nA web-based Cisco management interface is running on the remote host on TCP port ' +  port + '.\n';
    }

   # Citrix Access Gateway Administrative Web Interface
   app = 'citrix_access_gateway_admin';
   urls = pci_webapp_chk(app:app, port:port);
   if (!isnull(urls))
   {
     if ( max_index(urls) == 1) location = 'location';
     else location = 'locations';
     str += '\nCitrix Access Gateway Administrative Web Interface, a web-based management application for Citrix Access Gateway, is running on the remote host at the following ' +location + ' :\n';
     foreach url (urls)
     {
       str += '\n  '+url;
     }
     str += '\n';
   }

   # Cobbler Admin Interface
   app = 'cobbler_web_admin';
   urls = pci_webapp_chk(app:app, port:port);
   if (!isnull(urls))
   {
     if ( max_index(urls) == 1) location = 'location';
     else location = 'locations';
     str += '\nA web-based administration interface for Cobbler, a Linux distribution, is running on the remote host at the following ' +location + ' :\n';
     foreach url (urls)
     {
       str += '\n  '+url;
     }
     str += '\n';
   }

   # CodeMeter
   app = 'CodeMeter';
   urls = pci_webapp_chk(app:app, port:port);
   if (!isnull(urls))
   {
     if ( max_index(urls) == 1) location = 'location';
     else location = 'locations';
     str += '\nCodeMeter WebAdmin, a web-based management application for CodeMeter hardware and software, is running on the remote host at the following ' +location + ' :\n';
     foreach url (urls)
     {
       str += '\n  '+url;
     }
     str += '\n';
   }

   # HP Guardian Service Processor
   if (
     page &&
     '<TITLE>HP Web Console on' >< page &&
     '<APPLET CODE="pericom/TeemWorld/TeemWorld.class" ARCHIVE="TeemWorld.jar" ' >< page &&
     '<PARAM NAME=IPAddress' >< page
   )
   {
    str += '\nAn HP Guardian Service Processor interface is running on the remote host on TCP port ' +  port + '.\n';
   }

   # HP iLO
   if (
     page &&
     'Hewlett-Packard Development Company, L.P.' >< page &&
     (
       '<title>iLO 4</title>' >< page ||
       'id="titleHeading">iLO&nbsp;4</h1>' >< page ||
       '<title>iLO 3</title>' >< page ||
       'id="titleHeading">Integrated&nbsp;Lights-Out&nbsp;3</h1>' >< page ||
       '<TITLE>HP Integrated Lights-Out ' >< page
     )
   )
   {
    str += '\nAn HP Integrated Lights-Out (iLO) interface is running on the remote host on TCP port ' +  port + '.\n';
   }

   # HP Web Jetadmin
   app = 'hp_web_jetadmin';
   urls = pci_webapp_chk(app:app, port:port);
   if (!isnull(urls))
   {
     if ( max_index(urls) == 1) location = 'location';
     else location = 'locations';
     str += '\nHP Web Jetadmin, a web-based management application for networked printers, is running on the remote host at the following ' +location + ' :\n';
     foreach url (urls)
     {
       str += '\n  '+url;
     }
     str += '\n';
   }

   if ( page && '<form METHOD="POST" NAME="form" ACTION="/cgi-bin/home.tcl">' >< page &&
	        '<b>Acquire Exclusive Configuration Lock</b>' >< page )
   {
    str += '\nA web-based management interface is running on the remote host on TCP port ' + port + '.\n';
   }

   # MongoDB Web Admin Interface
   app = "mongodb_web";
   urls = pci_webapp_chk(app:app, port:port);
   if (!isnull(urls))
   {
     if ( max_index(urls) == 1) location = 'location';
     else location = 'locations';
     str += '\nMongoDB Web Admin Interface, a web-based MongoDB database management interface, is running on the remote host at the following ' +location + ' :\n';
     foreach url (urls)
     {
       str += '\n  '+url;
     }
     str += '\n';
   }

   # OpenAdmin Tool
   app = "openadmin_tool";
   urls = pci_webapp_chk(app:app, port:port);
   if (!isnull(urls))
   {
     if ( max_index(urls) == 1) location = 'location';
     else location = 'locations';
     str += '\nOpenAdmin Tool, a web-based tool for managing Informix database servers, is running on the remote host at the following ' +location + ' :\n';
     foreach url (urls)
     {
       str += '\n  '+url;
     }
     str += '\n';
   }

   # phpLDAPadmin
   app = "phpLDAPadmin";
   urls = pci_webapp_chk(app:app, port:port);
   if (!isnull(urls))
   {
     if ( max_index(urls) == 1) location = 'location';
     else location = 'locations';
     str += '\nphpLDAPadmin, a web-based LDAP management client, is running on the remote host at the following ' +location + ' :\n';
     foreach url (urls)
     {
       str += '\n  '+url;
     }
     str += '\n';
   }

   # phpMoAdmin
   app = "phpMoAdmin";
   urls = pci_webapp_chk(app:app, port:port);
   if (!isnull(urls))
   {
     if ( max_index(urls) == 1) location = 'location';
     else location = 'locations';
     str += '\nphpMoAdmin, a web-based MongoDB database management interface, is running on the remote host at the following ' +location + ' :\n';
     foreach url (urls)
     {
       str += '\n  '+url;
     }
     str += '\n';
   }

   # phpMyAdmin
   app = "phpMyAdmin";
   urls = pci_webapp_chk(app:app, port:port);
   if (!isnull(urls))
   {
     if ( max_index(urls) == 1) location = 'location';
     else location = 'locations';
     str += '\nphpMyAdmin, a web-based MySQL database management interface, is running on the remote host at the following ' +location + ' :\n';
     foreach url (urls)
     {
       str += '\n  '+url;
     }
     str += '\n';
   }

   # Pulse Connect Secure
   app = 'Pulse Connect Secure';
   urls = pci_webapp_chk(app:app, port:port);
   if (!isnull(urls))
   {
     if ( max_index(urls) == 1) location = 'location';
     else location = 'locations';
     str += '\nPulse Connect Secure, a Network Access Control server, is running on the remote host at the following ' +location + ' :\n';
     foreach url (urls)
     {
       str += '\n  '+url;
     }
     str += '\n';
   }

 }
}

# HP Onboard Administrator
hp_ports = get_kb_list('Host/HP/Onboard_Administrator/Port');
if (!isnull(hp_ports))
{
  foreach hp_port (hp_ports)
  {
    str += '\nAn HP Onboard Administrator interface is running on the remote host on TCP port ' + hp_port + '.\n';
  }
}

services = make_array(
  "ard",            "An Apple Remote Desktop server (remote administration)",
  "ca_rchost",      "A Unicenter Remote Control agent (remote administration)",
  "cifs",           "A CIFS server",
  "cisco-ssl-vpn-svr", "A Cisco ASA SSL VPN server (VPN)",
  "dameware",       "A DameWare server (remote administration)",
  "db2das",         "An IBM DB2 Administration Server",
  "db2das_connect", "An IBM DB2 Administration Server",
  "domino_console", "A Lotus Domino console",
  "ebsadmin",       "A McAfee E-Business Server (remote administration)",
  "egosecure_endpoint", "An EgoSecure EndPoint remote administration service",
  "ftp",            "An FTP server",
  "hydra_saniq",    "An HP LeftHand OSremote administration",
  "ike",            "An IKE server (VPN)",
  "inoweb",         "A Computer Associates administration server",
  "juniper_nsm_gui_svr", "A Juniper NSM GUI Server (remote administration)",
  "l2tp",           "An L2TP server (VPN)",
  "lgserver_admin", "An ARCserve Backup server",
  "linuxconf",      "A LinuxConf server (remote administration)",
  "mikrotik_mac_telnet", "A MikroTik MAC Telnet Protocol (remote administration)",
  "msrdp",          "A Terminal Services server (remote display)",
  "netbios-ns",     "A NETBIOS name server",
  "netbus",         "A NetBus remote administration tool",
  "netbus2",        "A NetBus remote administration tool",
  "openvpn",        "An OpenVPN server (VPN)",
  "pcanywhereaccessserver", "A Symantec pcAnywhere Access server (remote administration)",
  "pcanywheredata", "A pcAnywhere server (remote administration)",
  "pptp",           "A PPTP server (VPN)",
  "radmin",         "An Radmin server (remote administration)",
  "remote_pc",      "A Remote PC Access server (remote administration)",
  "rlogin",         "An rlogin server (remote terminal)",
  "rsh",            "An rsh server (remote terminal)",
  "smb",            "An SMB server",
  "ssh",            "An SSH server (remote terminal)",
  "synergy",        "A Synergy server (remote administration)",
  "teamviewer",     "A TeamViewer server (remote administration)",
  "telnet",         "A Telnet server (remote terminal)",
  "tftp",           "A TFTP server",
  "tinc_vpn",       "A Tinc VPN server (VPN)",
  "tor",            "A Tor relay (VPN)",
  "ultravnc-dsm",   "An UltraVNC server (remote display)",
  "veritas-ucl",    "A Symantec Veritas Enterprise Administrator Service",
  "vnc",            "A VNC server (remote display)",
  "vncviewer",      "A VNC Viewer listener (remote display)",
  "www/hp_smh",     "An HP System Management Homepage server (remote administration)",
  "www/logmein",    "A LogMeIn server (remote administration)",
  "www/webmin",     "A webmin server (remote administration)",
  "x11",            "An X11 server (remote display)"
);

foreach service (keys(services))
{
  desc = services[service];
  protos = make_array();
  ipprotos = make_list("TCP", "UDP");

  # Get TCP/UDP port(s) for each service
  foreach ipproto (ipprotos)
  {
    kb = NULL;
    if (ipproto == "TCP")      kb = "Services/" + service;
    else if (ipproto == "UDP") kb = "Services/udp/" + service;

    ports = get_kb_list(kb);
    if (empty_or_null(ports)) continue;

    ports = make_list(ports);
    protos[service][ipproto] = ports;
  }

  if (empty_or_null(protos)) continue;

  # Add to report
  foreach svc (keys(protos))
  {
    foreach proto (keys(protos[svc]))
    {
      ports = protos[svc][proto];
      index = max_index(ports);
      s = 's';
      sep = '';

      # Determine if 'and' or ', and' should be used
      if (index == 1) s = NULL;
      else if (index == 2) sep = ' and ';
      else if (index > 2)
      {
        ports[index-1] = 'and ' + ports[index-1];
        sep = ', ';
      }

      ports = join(ports, sep:sep);

      # E.g. An SSH server (remote terminal) is running on the remote host on TCP port 22.
      str += '\n'+desc+' is running on the remote host on '+proto+' port'+s+' '+ports+'.\n';
    }
  }
}

if (strlen(str) > 0)
{
  security_warning(extra:str, port:0);
}
