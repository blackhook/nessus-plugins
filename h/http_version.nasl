#
# Copyright 2000 by Hendrik Scholz <hendrik@scholz.net>
#
#
# @@NOTE: The output of this plugin should not be changed
#

# Changes by Tenable:
# - Revised plugin title (10/08/10)
# - Removed use of deprecated functions (01/16/2018)
# - Fixed various regular expression wildcards (01/16/2018)
# - Fixed logic so that server strings won't set multiple kb (01/16/2018)
# - Removed old Apache fingerprinting logic (01/16/2018) 
# - Fixed so many formatting issues (01/16/2018)
# - Added Aspen (03/13/2018)
# - Added NetVault (13/12/2018)
# - Added Lenel Embedded Web Server (01/25/2019)
# - Added Commvault WebServer (06/07/2019)

include("compat.inc");

if (description)
{
  script_id(10107);
  script_version("1.141");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/10/30");

  script_xref(name:"IAVT", value:"0001-T-0931");

  script_name(english:"HTTP Server Type and Version");
  script_summary(english:"HTTP Server type and version");

  script_set_attribute(attribute:"synopsis", value:"A web server is running on the remote host.");
  script_set_attribute(attribute:"description", value:
  "This plugin attempts to determine the type and the version of the
  remote web server.");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2000/01/04");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"asset_inventory", value:"True");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2000-2020 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"Web Servers");

  script_dependencies("find_service1.nasl", "http_login.nasl", "httpver.nasl", "no404.nasl", "www_fingerprinting_hmap.nasl", "webmin.nasl", "embedded_web_server_detect.nasl", "fake_http_server.nasl", "broken_web_server.nasl", "skype_detection.nasl", "www_server_name.nasl", "restricted_web_pages.nasl");
  script_require_ports("Services/www", 80);
  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http_func.inc");

#
# The script code starts here
#
global_var	port;

function get_domino_version()
{
 local_var req, soc, r, v;
 local_var whole_response, r_from_webroot, v_from_webroot;
 req = http_get(item:"/nonexistentdb.nsf", port:port);
 soc = http_open_socket(port);
 if(!soc) return NULL;
 send(socket:soc, data:req);
 r = egrep(pattern:".*Lotus-Domino .?Release", string:http_recv(socket:soc));
 http_close_socket(soc);
 v = NULL;
 if(r != NULL)v = ereg_replace(pattern:".*Lotus-Domino .?Release ([^ <]*).*", replace:"Lotus-Domino/\1", string:r);
 if(r == NULL || v == r )
 {
   # Attempt to get something from the '/' page which
   # contains a rough version number
   req = http_get(item:"/", port:port);
   soc = http_open_socket(port);
   if(!soc) return NULL;
   send(socket:soc, data:req);
   whole_response = http_recv(socket:soc);
   r_from_webroot = egrep(pattern:">Domino (Administrator [0-9.]+|[0-9.]+ Administrator) Help<", string:whole_response);
   http_close_socket(soc);

   v_from_webroot = NULL;
   if(r_from_webroot != NULL)
   {
     # Just an extra check since we're relying on strings
     # in HTML below; make sure Server header is good
     if ("Server: Lotus-Domino" >< whole_response)
     {
       # Early versions
       if ("Domino Administrator " >< r_from_webroot)
         v_from_webroot = ereg_replace(pattern:".*>Domino Administrator ([0-9.]+) Help<.*", replace:"Lotus-Domino/\1", string:r_from_webroot);
       # Later versions (9x)
       if ("Administrator Help" >< r_from_webroot)
         v_from_webroot = ereg_replace(pattern:".*>Domino ([0-9.]+) Administrator Help<.*", replace:"Lotus-Domino/\1", string:r_from_webroot);

       if (r_from_webroot == v_from_webroot)
         v_from_webroot = NULL;
     }
   }

   # Go ahead and attempt SMTP in case it can
   # provide more detail than '/' web request
   if(get_port_state(25))
   {
     soc = open_sock_tcp(25);
     if(soc)
     {
       r = recv_line(socket:soc, length:4096);
       close(soc);
       v = ereg_replace(pattern:".*(Lotus|IBM) Domino .?Release ([^)]*).*", replace:"Lotus-Domino/\2", string:r);

       if( v == r)
       {
         # Here we have nothing from normal .nsf method
         # and nothing from SMTP.
         # v_from_webroot will be NULL if there is nothing
         # from the '/' request, so return it ... no versions from anywhere.
         # v_from_webroot will contain a version if available
         # from the '/' request, so return it.
         return v_from_webroot;
       }
       else
       {
         if (max_index(split(v, sep:".")) >= max_index(split(v_from_webroot, sep:".")))
           return v;
         else
           return v_from_webroot;
       }
     }
     else
     {
       # Here there was nothing from .nsf method
       # and further, no socket to SMTP, so return
       # v_from_webroot. It will be either NULL or
       # will contain a rough version number
       return v_from_webroot;
     }
   }
   else
   {
     # Here there was nothing from .nsf method
     # and further, no SMTP port open, so return
     # v_from_webroot. It will be either NULL or
     # will contain a rough version number
     return v_from_webroot;
   }
 }
 else
  return v;
}

# This is the old function from http_func.inc: it may return embedded
# servers and closed ports
port = get_http_port(default:80, embedded:TRUE);
if (! get_port_state(port)) exit(0, "Port "+port+" is closed.");

# Allow some cheap optimization
if (get_kb_item("www/"+port+"/PHP") || can_host_php(port: port))
 set_kb_item(name:"www/PHP", value: TRUE);
if (get_kb_item("www/"+port+"/ASP") || can_host_asp(port: port))
 set_kb_item(name:"www/ASP", value: TRUE);

foreach k ( make_list("www/banner/"+port, "get_http", "www/alt-banner/"+port) )
{
  if ("/" >!< k)
  {
    resultrecv = get_kb_banner(port: port, type: k);
  }
  else
  {
    resultrecv = get_kb_item(k);
  }
  svrline = pgrep(string: resultrecv, pattern:"^Server:", icase:TRUE);
  if (svrline) break;
  svrline = pgrep(pattern:"^DAAP-Server:", string:resultrecv, icase: TRUE);
  if (svrline) break;
}

if (!svrline)
{
  soctcp80 = http_open_socket(port);
  if (! soctcp80) exit(1, "Connection refused on port "+port);

  data = http_get(item:"/", port:port);
  resultsend = send(socket:soctcp80, data:data);
  resultrecv = http_recv_headers2(socket:soctcp80);
  resbody = http_recv(socket:soctcp80);
  close(soctcp80);

  svrline = pgrep(pattern:"^Server:", string:resultrecv, icase:TRUE);
  if (! svrline)
    svrline = pgrep(pattern:"^DAAP-Server:", string:resultrecv, icase:TRUE);
  # nb: newer releases of WebSphere don't have a Server response header; 
  #     we'll add a fake one if there's otherwise no header and it looks 
  #     like it's WAS.
  if (!svrline && ':WASRemoteRuntimeVersion="' >< resbody) 
    svrline = "Server: WebSphere Application Server";
  # nnb: even newer releases of WebSphere don't have a WASRemoteRuntimeVersion
  #      SOAP-ENV Header;
  #      we'll now check for a few remaining header entries
  if (!svrline && ':JMXMessageVersion' >< resbody && ':JMXVersion' >< resbody)
    svrline = "Server: WebSphere Application Server";
}

svrline = chomp(svrline);
xpower = pgrep(string:resultrecv, pattern: "^X-Powered-By:", icase: 1);
svr = ereg_replace(pattern:"^[A-Z-]*Server: *(.*)$", string:svrline, replace:"\1", icase: 1);
svr = chomp(svr);
if (strlen(svr) == 0)
{
  exit(0, "No Server or DAAP-Server header on port "+port+".");
}

report = "";

if("Lotus-Domino" >< svr)
{
  if (preg(pattern:"Lotus-Domino/[1-9]\.[0-9]", string:svr))
  {
    report = report + svr;
  }
  else
  {
    svr2 = get_domino_version();
    if( svr2 != NULL )
    {
      report = report + svr2 + '\n\nThe product version is hidden but we could determine it by\n' +
        'requesting a nonexistent .nsf file, a default index file or connecting to port 25\n';
      svrline = "Server: "+ svr2+ '\r\n';
      replace_kb_item(name:"www/real_banner/" + port, value:svrline);

      if(!get_kb_item("www/banner/" + port))
      {
        replace_kb_item(name:"www/banner/" + port, value:svrline);
      }
    }
    else
    {
      report = report + svr;
    }
  }
}
else
{
  report = report + svr;
}

report = 'The remote web server type is :\n\n' + report;
security_note(port:port, extra:report);

#
# put the name of the web server in the KB
#
if (preg(pattern:"^Server:.*(Apache.* Tomcat|Apache-Coyote)/", string:svrline, icase:TRUE))
{
  # Server: Apache Tomcat/5.0.12
  # Server: Apache-Coyote/1.1
  set_kb_item(name:"www/tomcat", value:TRUE);
}
else if (preg(pattern:"^Server:.*StWeb", string:svrline))
{
  # Server: Apache/2.0.63 (Unix) StWeb-MySql/2.0
  set_kb_item(name:"www/stweb", value:TRUE);
  set_kb_item(name:"www/apache", value:TRUE);
}
else if (preg(pattern:"^Server:.*Oracle HTTP Server", string:svrline))
{
  set_kb_item(name:"www/OracleApache", value:TRUE);
  set_kb_item(name:"www/apache", value:TRUE);
}
else if (preg(pattern:"^Server:.*Stronghold", string:svrline))
{
  # Server: Stronghold/2.2 Apache/1.2.5 C2NetUS/2002/php3.0.3
  set_kb_item(name:"www/stronghold", value:TRUE);
  set_kb_item(name:"www/apache", value:TRUE);
}
else if (preg(pattern:"^Server:.*Apache", string:svrline))
{
  # Server: Apache/2.2.15 (CentOS)
  set_kb_item(name:"www/apache", value:TRUE);
}
else if (preg(pattern:"^Server:.*Microsoft", string:svrline))
{
  # Server: Microsoft-IIS/7.5
  # Server: Microsoft-HTTPAPI/2.0
  set_kb_item(name:"www/iis", value:TRUE);
}
else if (preg(pattern:"^Server:.*nginx", string:svrline))
{
  # Server: nginx/1.2.1
  set_kb_item(name:"www/nginx", value:TRUE);
}
else if (preg(pattern:"^Server:.*nostromo", string:svrline))
{
  # Server: nostromo 1.9.5
  set_kb_item(name:"www/nostromo", value:TRUE);
}
else if (preg(pattern:"^Server:.*Unit", string:svrline))
{
  # Server: Unit/1.7.1
  set_kb_item(name:"www/nginx_unit", value:TRUE);
}
else if (preg(pattern:"^Server:.*lighttpd", string:svrline, icase:TRUE))
{
  # Server: lighttpd
  # Server: lighttpd/1.4.39
  # Server: lighttpd/1.4.28-devel-14932
  # Server: LightTPD/1.4.39-1-IPv6 (Win32)
  set_kb_item(name:"www/lighttpd", value:TRUE);
}
else if (preg(pattern:"^Server:.*UPnP", string:svrline, icase:TRUE))
{
  # SERVER: miniupnpd/1.0 UPnP/1.0
  # Server: RomPager/4.07 UPnP/1.0
  # SERVER: Linux/3.0.8, UPnP/1.0, Portable SDK for UPnP devices/1.6.19
  set_kb_item(name:"www/upnp", value:TRUE);
  if ("RomPager" >< srvline)
  {
    set_kb_item(name:"www/allegro", value:TRUE);
  }
}
else if (preg(pattern:"^Server: RomPager", string:svrline) ||
         preg(pattern:"^Server:.*Allegro-Software-RomPager", string:svrline))
{
  # Server: RomPager/4.07 UPnP/1.0
  # Server: Allegro-Software-RomPager/5.40
  set_kb_item(name:"www/allegro", value:TRUE);
}
else if (preg(pattern:"^Server:.*[Ss]quid", string:svrline))
{
  # Server: squid/3.5.25
  set_kb_item(name:"www/squid", value:TRUE);
}
else if (preg(pattern:"^Server:.*Domino", string:svrline))
{
  # Server: Lotus-Domino
  set_kb_item(name:"www/domino", value:TRUE);
}
else if (preg(pattern:"^Server:.*GoAhead-(Webs|http)", string:svrline))
{
  # Server: GoAhead-Webs
  set_kb_item(name:"www/goahead", value:TRUE);
}
else if (preg(pattern:"^Server:.*Zope", string:svrline))
{
   # Server: Zope/(2.13.16, python 2.7.3, linux2) ZServer/1.1
   set_kb_item(name:"www/zope", value:TRUE);
}
else if (preg(pattern:"^Server:.*CERN", string:svrline))
{
   # Host: CERN httpd
   set_kb_item(name:"www/cern", value:TRUE);
}
else if (preg(pattern:"^Server: uc-httpd/"))
{
  # Server: uc-httpd/1.0.0
  set_kb_item(name:"www/uc-httpd", value:TRUE);
}
else if (preg(pattern:"^Server:.*Zeus", string:svrline))
{
   # Server: Zeus/4.3
   set_kb_item(name:"www/zeus", value:TRUE);
}
else if (preg(pattern:"^Server:.*WebSitePro", string:svrline))
{
   # Server: WebSitePro/2.5.8
   set_kb_item(name:"www/websitepro", value:TRUE);
}
else if (preg(pattern:"^Server:.*NCSA", string:svrline))
{
  # Server: NCSA/1.3
  set_kb_item(name:"www/ncsa", value:TRUE);
}
else if (preg(pattern:"^Server:.*Netscape-Enterprise", string:svrline))
{
  # Server: Netscape-Enterprise/6.0
  set_kb_item(name:"www/iplanet", value:TRUE);
}
else if (preg(pattern:"^Server:.*Netscape-Administrator", string:svrline))
{
  # Server: Netscape-Administrator/2.0
  set_kb_item(name:"www/iplanet", value:TRUE);
}
else if (preg(pattern:"^Server:.*PanWeb Server/", string:svrline))
{
  # Server: PanWeb Server/ -
  set_kb_item(name:"www/panweb", value:TRUE);
}
else if (preg(pattern:"^Server:.*thttpd/", string:svrline))
{
  # Server: thttpd/2.25b 29dec2003
  set_kb_item(name:"www/thttpd", value:TRUE);
}
else if (preg(pattern:"^Server:.*WDaemon", string:svrline))
{
  # Server: WDaemon/4.0
  set_kb_item(name:"www/wdaemon", value:TRUE);
}
else if (preg(pattern:"^Server:.*SAMBAR", string:svrline))
{
  # Server: SAMBAR
  set_kb_item(name:"www/sambar", value:TRUE);
}
else if (preg(pattern:"^Server:.*IBM[- _]HTTP[- _]Server", string:svrline))
{
  # Server: IBM_HTTP_Server
  set_kb_item(name:"www/ibm-http", value:TRUE);
}
else if (preg(pattern:"^Server:.*Alchemy", string:svrline))
{
  # Server: Alchemy Eye/11.5.0
  set_kb_item(name:"www/alchemy", value:TRUE);
}
else if (preg(pattern:"^Server:.*CommuniGatePro", string:svrline))
{
  # Server: CommuniGatePro/5.3.12
  set_kb_item(name:"www/communigatepro", value:TRUE);
}
else if (preg(pattern:"^Server:.*Savant", string:svrline))
{
  # Server: Savant/3.1
  set_kb_item(name:"www/savant", value:TRUE);
}
else if (preg(pattern:"^Server:.*WebSphere Application Server", string:svrline))
{
  # Server: WebSphere Application Server/6.1
  set_kb_item(name:"www/WebSphere", value:TRUE);
}
else if (preg(pattern:"^Server:.*MiniServ", string:svrline))
{
  # Server: MiniServ/1.840
  set_kb_item(name:"www/miniserv", value:TRUE);
}
else if (preg(pattern:"^Server:.*mini_httpd", string:svrline))
{
  # Server: mini_httpd/1.19 19dec2003
  set_kb_item(name:"www/mini_httpd", value:TRUE);
}
else if (preg(pattern:"^Server:.*vqServer", string:svrline))
{
  # Server: vqServer/1.9.55 The world's most friendly web server
  set_kb_item(name:"www/vqserver", value:TRUE);
}
else if (preg(pattern:"^Server:.*VisualRoute", string:svrline))
{
  # Server: VisualRoute (R) 2008 Server NOC Edition (v12.0i)
  set_kb_item(name:"www/visualroute", value:TRUE);
}
else if (preg(pattern:"^Server:.*OmniHTTPd", string:svrline))
{
  # Server: OmniHTTPd/2.06
  set_kb_item(name:"www/omnihttpd", value:TRUE);
}
else if (preg(pattern:"^Server:.*WebSTAR", string:svrline))
{
  # Server: WebSTAR/4.1 ID/73666
  set_kb_item(name:"www/webstar", value:TRUE);
}
else if (preg(pattern:"^Server:.*Oracle.*Server", string:svrline))
{
  # Server: Oracle-HTTP-Server-11g
  set_kb_item(name:"www/oracle", value:TRUE);
}
else if (preg(pattern:"^Server:.*AppleShareIP", string:svrline))
{
  # Server: AppleShareIP/6.3.3
  set_kb_item(name:"www/appleshareip", value:TRUE);
}
else if (preg(pattern:"^Server:.*Jigsaw", string:svrline))
{
  # Server: Jigsaw/2.0.4
  set_kb_item(name:"www/jigsaw", value:TRUE);
}
else if (preg(pattern:"^Server:.*Resin", string:svrline))
{
  # Server: Resin/4.0.45
  set_kb_item(name:"www/resin", value:TRUE);
}
else if (preg(pattern:"^Server:.*AOLserver", string:svrline))
{
  # Server: AOLserver/4.5.1
  set_kb_item(name:"www/aolserver", value:TRUE);
}
else if (preg(pattern:"^Server:.*IdeaWebServer", string:svrline))
{
  # Server: IdeaWebServer/v0.80
  set_kb_item(name:"www/ideawebserver", value:TRUE);
}
else if (preg(pattern:"^Server:.*FileMakerPro", string:svrline))
{
  # Server: FileMakerPro/4.0
  set_kb_item(name:"www/filemakerpro", value:TRUE);
}
else if (preg(pattern:"^Server:.*NetWare-Enterprise-Web-Server", string:svrline))
{
  # Server: NetWare-Enterprise-Web-Server/5.1
  set_kb_item(name:"www/netware", value:TRUE);
}
else if (preg(pattern:"^Server:.*Roxen", string:svrline))
{
  # Server: Roxen/2.1.265
  set_kb_item(name:"www/roxen", value:TRUE);
}
else if (preg(pattern:"^Server:.*SimpleServer:WWW", string:svrline))
{
  # Server: SimpleServer:WWW/1.23
  set_kb_item(name:"www/simpleserver", value:TRUE);
}
else if (preg(pattern:"^Server:.*Xitami", string:svrline))
{
  # Server: Xitami
  set_kb_item(name:"www/xitami", value:TRUE);
}
else if (preg(pattern:"^Server:.*EmWeb", string:svrline))
{
  # Server: Virata-EmWeb/R6_2_0
  set_kb_item(name:"www/emweb", value:TRUE);
}
else if (preg(pattern:"^Server:.*Ipswitch-IMail", string:svrline))
{
  # Server: Ipswitch-IMail/8.05
  set_kb_item(name:"www/ipswitch-imail", value:TRUE);
}
else if (preg(pattern:"^Server:.*Netscape-FastTrack", string:svrline))
{
  # Server: Netscape-FastTrack/2.0a
  set_kb_item(name:"www/netscape-fasttrack", value:TRUE);
}
else if (preg(pattern:"^Server:.*AkamaiGHost", string:svrline))
{
  # Server: AkamaiGHost
  set_kb_item(name:"www/akamaighost", value:TRUE);
}
else if (preg(pattern:"^Server:.*Netscape-Commerce", string:svrline))
{
  # Server: Netscape-Commerce/1.12
  set_kb_item(name:"www/netscape-commerce", value:TRUE);
}
else if (preg(pattern:"^Server:.*Oracle_Web_listener", string:svrline))
{
  # Server: Oracle_Web_Listener/4.0.8.1.0EnterpriseEdition
  set_kb_item(name:"www/oracle-web-listener", value:TRUE);
}
else if (preg(pattern:"^Server:.*Caudium", string:svrline))
{
  # Server: Caudium/1.4.12 STABLE (Debian GNU/Linux)
  set_kb_item(name:"www/caudium", value:TRUE);
}
else if (preg(pattern:"^Server:.*Cougar", string:svrline))
{
  # Server: Cougar/9.6.7600.16564
  set_kb_item(name:"www/cougar", value:TRUE);
}
else if (preg(pattern:"^Server:.*NetCache", string:svrline))
{
  # Server: NetCache appliance (NetApp/6.1.1D8)
  set_kb_item(name:"www/netcache", value:TRUE);
}
else if (preg(pattern:"^Server:.*AnWeb", string:svrline))
{
  # Server: AnWeb/1.42p
  set_kb_item(name:"www/anweb", value:TRUE);
}
else if (preg(pattern:"^Server:.*Pi3Web", string:svrline))
{
  # Server: Pi3Web/2.0.3
  set_kb_item(name:"www/pi3web", value:TRUE);
}
else if (preg(pattern:"^Server:.*TUX", string:svrline))
{
  # Server: TUX/2.0 (Linux)
  set_kb_item(name:"www/tux", value:TRUE);
}
else if (preg(pattern:"^Server:.*Abyss", string:svrline))
{
  # Server: Abyss/2.9.3.6-X1-Win32 AbyssLib/2.9.3.6
  set_kb_item(name:"www/abyss", value:TRUE);
}
else if (preg(pattern:"^Server:.*Jetty", string:svrline))
{
  # Server: Jetty(8.1.15.v20140411)
  set_kb_item(name:"www/jetty", value:TRUE);
}
else if (preg(pattern:"^Server:.*CUPS(/.*)?$", string:svrline))
{
  # Server: CUPS/1.5
  set_kb_item(name:"www/cups", value:TRUE);
}
else if (preg(pattern:"^Server:.*Novell-HTTP-Server", string:svrline))
{
  # Server: Novell-HTTP-Server/3.1R1
 	set_kb_item(name:"www/novell", value:TRUE);
}
else if (preg(pattern:"^Server:.*theServer/", string:svrline))
{
  # Server: TheServer/2.37L
 	set_kb_item(name:"www/theserver", value:TRUE);
}
else if (preg(pattern:"^Server:.*WWW File Share", string:svrline))
{
  # Server: WWW File Share Pro
  set_kb_item(name:"www/wwwfileshare", value:TRUE);
}
else if (preg(pattern:"^Server: *eMule", string:svrline))
{
  # Server: eMule
  set_kb_item(name:"www/eMule", value:TRUE);
}
else if (preg(pattern:"^Server:.*HP System Management Homepage/?", string:svrline))
{
  # Server: CompaqHTTPServer/9.9 HP System Management Homepage
  set_kb_item(name:"www/hpsmh", value:TRUE);
  set_kb_item(name:"www/compaq", value:TRUE);
}
else if (preg(pattern:"^Server:.*CompaqHTTPServer", string:svrline))
{
  # Server: CompaqHTTPServer/9.9 HP System Management Homepage
  set_kb_item(name:"www/compaq", value:TRUE);
}
else if (preg(pattern:"^Server: *Xerver", string:svrline))
{
  # Server: Xerver/4.32
  set_kb_item(name:"www/xerver", value:TRUE);
}
else if (preg(pattern:"Server:.*CherryPy/", string:svrline))
{
  # Server: CherryPy/5.1.0
  set_kb_item(name:"www/cherrypy", value:TRUE);
}
else if (preg(pattern:"Server:.*Wing FTP Server/", string:svrline))
{
  # Sever: Wing FTP Server()
  set_kb_item(name:"www/wingftp", value:TRUE);
}
else if (preg(pattern:"Server:.*SmarterTools/", string:svrline))
{
  # Server: SmarterTools/2.0.4310.28347
  set_kb_item(name:"www/smartertools", value:TRUE);
}
else if (preg(pattern:"Server: *PRTG/", string:svrline))
{
  # Server: PRTG/17.3.32.2478
  set_kb_item(name:"www/prtg", value:TRUE);
}
else if (preg(pattern:"Server: ATS/", string:svrline))
{
  # Server: ATS/7.0.0
  set_kb_item(name:"www/apache_traffic_server", value:TRUE);
}
else if (preg(pattern:"Server: *TornadoServer/", string:svrline))
{
  # Server: TornadoServer/5.0.dev1
  set_kb_item(name:"www/tornado", value:TRUE);
}
else if (preg(pattern:"Server: *((Embedthis-(Appweb|http))|Mbedthis-Appweb)/", string:svrline))
{
  # Server: Mbedthis-Appweb/2.4.0
  # Server: Embedthis-http
  set_kb_item(name:"www/appweb", value:TRUE);
}
else if (preg(pattern:"Server: BigFixHTTPServer/", string:svrline))
{
  # Server: BigFixHTTPServer/9.5.5.193
  set_kb_item(name:"www/BigFixHTTPServer", value:TRUE);
}
else if (preg(pattern:"Server: KS_HTTP/", string:svrline))
{
  # Server: KS_HTTP/1.0
  set_kb_item(name:"www/KS_HTTP", value:TRUE);
}
else if (preg(pattern:"Server: 3Com/", string:svrline))
{
  # Server: 3Com/v1.0
  set_kb_item(name:"www/3com", value:TRUE);
}
else if (preg(pattern:"Server: IPWEBS/", string:svrline))
{
  # Server: IPWEBS/1.4.0
  set_kb_item(name:"www/ipwebs", value:TRUE);
}
else if (preg(pattern:"^Server:.*linuxconf", string:svrline))
{
  set_kb_item(name:"www/linuxconf", value:TRUE);
}
else if (preg(pattern:"Server:.*GroupWise GWIA ", string:svrline))
{
  set_kb_item(name:"www/groupwise-ia", value:TRUE);
}
else if (preg(pattern:"Server:.*MagnoWare/", string:svrline))
{
  set_kb_item(name:"www/magnoware", value:TRUE);
}
else if (preg(pattern:"^Server:.*IceWarp", string:svrline))
{
  set_kb_item(name:"www/icewarp", value:TRUE);
}
else if (preg(pattern:"^Server:.*BCReport", string:svrline))
{
  set_kb_item(name:"www/BCReport", value:TRUE);
}
else if (preg(pattern:"^Server:.*Blue Coat Reporter", string:svrline))
{
  set_kb_item(name:"www/BCReport", value:TRUE);
}
else if (preg(pattern:"^Server:.*bkhttp/", string:svrline))
{
  set_kb_item(name:"www/BitKeeper", value:TRUE);
}
else if (preg(pattern:"^Server:.*[aA]libaba", string:svrline))
{
  set_kb_item(name:"www/alibaba", value:TRUE);
}
else if (preg(pattern:"^Server:.*KeyFocus Web Server", string:svrline))
{
  set_kb_item(name:"www/KFWebServer", value:TRUE);
}
else if (preg(pattern:"^Server:.*WebServer 4 Everyone", string:svrline))
{
  set_kb_item(name:"www/webserver4everyone", value:TRUE);
}
else if (preg(pattern:"^Server:.*BadBlue", string:svrline))
{
  set_kb_item(name:"www/badblue", value:TRUE);
}
else if (preg(pattern:"^Server:.*FirstClass", string:svrline))
{
  set_kb_item(name:"www/firstclass", value:TRUE);
}
else if (preg(pattern:"^Server:.*tigershark", string:svrline))
{
  set_kb_item(name:"www/tigershark", value:TRUE);
}
else if (preg(pattern:"^Server:.*Statistics Server", string:svrline))
{
  set_kb_item(name:"www/statistics-server", value:TRUE);
}
else if (preg(pattern:"^Server:.*Aspen/", string:svrline))
{
  set_kb_item(name:"www/aspen", value:TRUE);
}
else if (preg(pattern:"^Server:.*NetVault/", string:svrline))
{
  set_kb_item(name:"www/netvault", value:TRUE);
}
else if (preg(pattern:"^Server:.*Oracle (XML DB|Database)", string:svrline))
{
  # Server: Oracle XML DB/Oracle Database
  set_kb_item(name:"www/oracledb", value:TRUE);
  set_kb_item(name:"www/oracledb/port", value:port);
}
else if (preg(pattern:"^(S|s)erver:.*Lenel Embedded Web Server/", string:svrline))
{
  set_kb_item(name:"www/lenel_embedded_web_server", value:TRUE);
}
else if (preg(pattern:"^Server:.*Commvault WebServer", string:svrline))
{
  set_kb_item(name:"www/commvault_webserver", value:TRUE);
}

####
if (xpower)
{
  if ("JBoss" >< xpower)
  {
    set_kb_item(name: 'www/jboss', value: TRUE);
  }
}
