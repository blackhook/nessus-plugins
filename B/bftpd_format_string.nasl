#
# (C) Tenable Network Security, Inc.
#
# Script audit and contributions from Carmichael Security
#      Erik Anderson <eanders@carmichaelsecurity.com> (nb: this domain no longer exists)
#      Added link to the Bugtraq message archive
#


include("compat.inc");


if(description)
{
 script_id(10568);
 script_version ("1.41");
 
 script_name(english:"bftpd NLST Command Output Format String");
 script_summary(english:"Checks if the remote bftpd daemon is vulnerable to a format string attack");
 
 script_set_attribute(
   attribute:"synopsis",
   value:"The remote FTP server has a format string vulnerability."
 );
 script_set_attribute(attribute:"description", value:
"The remote FTP server, which appears to be Bftpd, has a format
string vulnerability in the NLST command.  A remote attacker could use
this to crash the service, or possibly execute arbitrary code." );
 script_set_attribute(
   attribute:"see_also",
   value:"https://marc.info/?l=bugtraq&m=97614485204378&w=2"
 );
 script_set_attribute(
   attribute:"solution", 
   value:"Upgrade to Bftpd 1.0.13 or later."
 );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L");
 script_set_attribute(attribute:"cvss_score_source", value:"manual");
 script_set_attribute(attribute:"cvss_score_rationale", value:"score from a more in depth analysis done by Tenable");
 script_set_attribute(attribute:"plugin_publication_date", value: "2000/12/11");
 script_set_attribute(attribute:"vuln_publication_date", value: "2000/12/06");
 script_cvs_date("Date: 2018/11/15 20:50:22");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_MIXED_ATTACK);
 script_family(english:"FTP");

 script_copyright(english:"This script is Copyright (C) 2000-2018 and is owned by Tenable, Inc. or an Affiliate thereof.");
                  
 script_dependencies("ftpserver_detect_type_nd_version.nasl", "ftp_anonymous.nasl", "ftp_writeable_directories.nasl" );
 script_require_ports("Services/ftp", 21);

 exit(0);
}

#
# The script code starts here : 
#

include("ftp_func.inc");

login = get_kb_item("ftp/login");
pass  = get_kb_item("ftp/password");


port = get_ftp_port(default:21);
banner = get_ftp_banner(port:port);
if( !banner || !egrep( pattern:"220.*bftpd 1\.0\.(([0-9][^0-9])|(1[0-2]))", string:banner ) ) exit(0);

dir   = get_kb_item("ftp/"+port+"/writeable_dir");
if (! dir) dir = get_kb_item("ftp/writeable_dir");


# Connect to the FTP server
soc = open_sock_tcp(port);
if (! soc) exit(1, "Cannot connect to TCP port "+port+".");
ftp_debug(str:"custom banner");

 if(login && dir && safe_checks() == 0 )
 {
 if(ftp_authenticate(socket:soc, user:login, pass:pass))
 {
  # We are in
  c = ('CWD ' + dir + '\r\n');
  send(socket:soc, data:c);
  ftp_recv_line(socket:soc);
  c = ('MKD Nessus_test\r\n');
  send(socket:soc, data:c);
  r = ftp_recv_line(socket:soc);
  if(egrep(pattern:"^(257|451)", string:r))
  {
  c = ('CWD Nessus_test\r\n');
  send(socket:soc, data:c);
  r = ftp_recv_line(socket:soc);
  
  c = ('MKD %p%p%p%p\r\n');
  send(socket:soc, data:c);
  r = ftp_recv_line(socket:soc);
  port2 = ftp_pasv(socket:soc);
  soc2 = open_sock_tcp(port2, transport:get_port_transport(port));
  if ( ! soc2 ) exit(1, "Cannot connect to TCP port "+port2+".");
  
  c = ('NLST\r\n');
  send(socket:soc, data:c);
  r = ftp_recv_listing(socket:soc2);
  if(preg(pattern:".*0x[a-f,A-F,0-9]*0x[a-f,A-F,0-9]*0x[a-f,A-F,0-9].*",
  	  string:r))security_hole(port);
  close(soc2);	  
  ftp_close(socket:soc);
  
  soc = open_sock_tcp(port);
  if(!soc)exit(1, "Cannot connect to TCP port "+port+".");
  ftp_authenticate(socket:soc, user:login, pass:pass);
  send(socket:soc, data:('CWD ' + dir + '/Nessus_test\r\n'));
  ftp_recv_line(socket:soc);
  send(socket:soc, data:('RMD %p%p%p%p\r\n'));
  r = ftp_recv_line(socket:soc);
  send(socket:soc, data:('CWD ..\r\n'));
  r = ftp_recv_line(socket:soc);
  send(socket:soc, data:('RMD Nessus_test\r\n'));
  r = ftp_recv_line(socket:soc);
  ftp_close(socket:soc);
  exit(0);
  }
   else {
    	close(soc);
	soc = open_sock_tcp(port);
	if ( ! soc ) exit(1, "Cannot connect to TCP port "+port+".");
	}
 }
  else {
  	close(soc);
	soc = open_sock_tcp(port);
	if ( ! soc ) exit(1, "Cannot connect to TCP port "+port+".");
	}
 }
  r = ftp_recv_line(socket:soc);
  close(soc);
  if(egrep(pattern:"220.*bftpd 1\.0\.(([0-9][^0-9])|(1[0-2]))",
  	 string:r)){
	 report = (
           '\nNessus only verified this vulnerability exists by looking at\n' +
           'banner, so this may be a false positive.\n'
         );
	 security_hole(port:port, extra:report);
	 }
