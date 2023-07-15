#
# (C) Tenable Network Security, Inc.
#

# Some information:
# http://www.nessus.org/u?31a1871a
# http://www.nessus.org/u?6ad5fd00
# http://www.nessus.org/u?99e99399

include("compat.inc");

if (description)
{
 script_id(19288);
 script_version("1.30");
 script_set_attribute(attribute:"plugin_modification_date", value:"2021/07/13");

 script_name(english:"VNC Server Security Type Detection");
 script_summary(english:"Identifies the RFB protocol version (VNC) & security types");

 script_set_attribute(attribute:"synopsis", value:"A VNC server is running on the remote host.");
 script_set_attribute(attribute:"description", value:
"This script checks the remote VNC server protocol version and the
available 'security types'.");
 script_set_attribute(attribute:"solution", value:"n/a");
 script_set_attribute(attribute:"risk_factor", value:"None");

 script_set_attribute(attribute:"plugin_publication_date", value:"2005/07/22");

 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2005-2021 Tenable Network Security, Inc.");
 script_family(english:"Service detection");

 script_dependencies("vnc.nasl");
 script_require_ports("Services/vnc", 5900);
 exit(0);
}

include('global_settings.inc');
include('dump.inc');
include('misc_func.inc');
include('network_func.inc');
include("debug.inc");


function connection_refused(port, socket)
{
 local_var i, is_printable, reason, r, l, report;

 reason = '';

 r = recv(socket: socket, min: 4, length: 4);
 if (strlen(r) == 4)
 {
   l = ntohl(n: r);
   reason = recv(socket: socket, length: l);
 }
 report = '\nThe remote VNC server rejected the connection.\n';

 is_printable = TRUE;
 l = strlen(reason);
 for (i=0; i<l; i++)
   if (!isprint(c:reason[i]))
   {
     is_printable = FALSE;
     break;
   }

 if (l > 0 && is_printable)
   report += 'Reason : ' + reason;
 else
   report += 'Nessus could not determine why.';

 security_note(port:port, extra:report);
}

port = get_kb_item("Services/vnc");

if (! port) port = 5900;	# or 5901, 5902...?

if (! get_port_state(port)) audit(AUDIT_PORT_CLOSED, port);

s = open_sock_tcp(port);
if(! s) audit(AUDIT_SOCK_FAIL, port, "TCP");

r = recv(socket: s, length: 512, min: 12);
dbg::log(src:SCRIPT_NAME, msg:"r1:", ddata:r);

if (strlen(r) < 12)
{
  dbg::log(src:SCRIPT_NAME, msg:"Error: strlen of response was less than 12 chars");  
  audit(AUDIT_RESP_BAD, port, "the RFB request");
}

v = pregmatch(string: r, pattern: '^RFB ([0-9]+)\\.([0-9]+)\n');
if (isnull(v))
{
  dbg::log(src:SCRIPT_NAME, msg:"Error: Failed to match RFB in response");
  audit(AUDIT_RESP_BAD, port, "the RFB request");
}

if ( "Too many security failures" >< r )
{
 close(s);
 dbg::log(src:SCRIPT_NAME, msg:"Waiting 20 seconds due to Security Failure");  
 sleep(20); # http://kb.realvnc.com/questions/23/I'm+receiving+the+error+%22'Too+many+security+failures%22.

 s = open_sock_tcp(port);
 if(! s) audit(AUDIT_SOCK_FAIL, port, "TCP");

 r = recv(socket: s, length: 512, min: 12);
 dbg::log(src:SCRIPT_NAME, msg:"r2:", ddata:r);

 if (strlen(r) < 12)
 {
   dbg::log(src:SCRIPT_NAME, msg:"Error: strlen of response was less than 12 chars");  
   audit(AUDIT_RESP_BAD, port, "the RFB request");
 }

 v = pregmatch(string: r, pattern: '^RFB ([0-9]+)\\.([0-9]+)\n');
 if (isnull(v))
 {
   dbg::log(src:SCRIPT_NAME, msg:"Error: Failed to match RFB in response");
   audit(AUDIT_RESP_BAD, port, "the RFB request");
 }
}

major = int(v[1]);
minor = int(v[2]);

dbg::log(src:SCRIPT_NAME, msg:"RFB protocol version = " + major + "." + minor + "\n");

set_kb_item(name: 'RFB/version/'+port, value: strcat(major, '.', minor));

if (major < 3)
{
  dbg::log(src:SCRIPT_NAME, msg:"Error: Major version value found to be less than 3");
  audit(AUDIT_HOST_NOT, "affected");
}

# Send back the same protocol
send(socket: s, data: r);

# Security types names
rfb_sec = make_array(
 -6, "MS Logon (UltraVNC)",
 0, "Invalid (connection refused)",
 1, "None",
 2, "VNC authentication",
 5, "RA2",
 6, "RA2ne",
 16, "Tight",
 17, "Ultra",
 18, "TLS",
 19, "VeNCrypt",
 20, "GTK-VNC SASL",
 21, "MD5 hash authentication",
 22, "Colin Dean xvp",
 30, "Mac OSX SecType 30",
 35, "Mac OSX SecType 35"
);

if (major == 3 && minor >= 3 && minor < 7)
{
 r = recv(socket: s, min: 4, length: 4);
 dbg::log(src:SCRIPT_NAME, msg:"r3:", ddata:r);

 if (strlen(r) != 4)
 {
   dbg::log(src:SCRIPT_NAME, msg:"Error: Length of response was not 4, as expected");
   audit(AUDIT_RESP_BAD, port, "the RFB request");
 }

 st = ntohl(n: r);
 if (st == 0)
 {
  connection_refused(port: port, socket: s);
 }
 else
 {
  set_kb_item(name: 'VNC/SecurityType/'+port, value: st);
  report = strcat('The remote VNC server chose security type #', st);
  if (rfb_sec[st])
    report = strcat(report, ' (', rfb_sec[st], ')');

  if (st == 1)
    set_kb_item(name: 'VNC/SecurityNoAuthentication', value:port);

   report = strcat("\n",report);

   security_note(port: port, extra: report);
 }
}
else if (major > 3 || minor >= 7)
{
 r = recv(socket: s, min: 1, length: 1);
 dbg::log(src:SCRIPT_NAME, msg:"r4:", ddata:r);

 if (strlen(r) < 1)
 {
   dbg::log(src:SCRIPT_NAME, msg:"Error: Length of response less than 1");
   audit(AUDIT_RESP_BAD, port, "the RFB request");
 }

 n = ord(r);
 if (n == 0)	# rejected connection
 {
  connection_refused(port: port, socket: s);
 }
 else
 {
  report = '';
  types = make_list();
  for (i = 0; i < n; i ++)
  {
   r = recv(socket: s, min: 1, length: 1);
   dbg::log(src:SCRIPT_NAME, msg:"r5:", ddata:r);

   if (strlen(r) < 1)
     break;
   st = ord(r);

   types = list_uniq(make_list(types, st));

   if (st == 1)
    set_kb_item(name: 'VNC/SecurityNoAuthentication', value:port);
  }

  foreach var thistype (types)
  {
   set_kb_item(name: 'VNC/SecurityType/'+port, value: thistype);
   if (rfb_sec[thistype])
    report = strcat(report, '  ', thistype, ' (', rfb_sec[thistype], ')', '\n');
   else
    report = strcat(report, '  ', '  ', thistype, '\n');
  }

  if (report)
  {
   if (max_index(split(report)) > 1) s = "s";
   else s = "";

   report = strcat('\n', 
     "The remote VNC server supports the following security type", s, " :\n", 
     "\n",
     report);

   security_note(port: port, extra: report);
  }
 }
}
else
{
  dbg::log(src:SCRIPT_NAME, msg:"Error: Determined version unexpected\nmajor: " + major + "\nminor: " + minor + "\n");
  audit(AUDIT_HOST_NOT, "affected");
}

if (service_is_unknown(port: port))
  register_service(port: port, proto: 'vnc');
