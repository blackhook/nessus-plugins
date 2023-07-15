# 
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


# References:
#
# Date: 2 Jun 2003 16:55:10 -0000
# From: Luca Ercoli <luca.ercoli@inwind.it>
# To: bugtraq@securityfocus.com
# Subject: Format String Vulnerability in Crob Ftp Server

if(description)
{
 script_id(11687);
 script_bugtraq_id(7776);
 script_xref(name:"Secunia", value:"8929");
 script_version ("1.21");
 
 script_name(english:"Crob FTP Server user Field Remote Format String");
 script_summary(english:"Logs as a %x");

 script_set_attribute(
   attribute:"synopsis",
   value:"The remote FTP server has a format string vulnerability."
 );
 script_set_attribute(attribute:"description", value:
"The version of Crob FTP server running on the remote host has a format
string vulnerability when processing the USER command.  A remote
attacker could exploit this to crash the service, or possibly execute
arbitrary code." );
 script_set_attribute(
   attribute:"see_also",
   value:"https://seclists.org/bugtraq/2003/Jun/27"
 );
 script_set_attribute(
   attribute:"solution", 
   value:"Upgrade to Crob FTP server 2.50.10 or later."
 );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
 script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
 script_set_attribute(attribute:"cvss_score_source", value:"manual");
 script_set_attribute(attribute:"cvss_score_rationale", value:"score from a more in depth analysis done by Tenable");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"plugin_publication_date", value: "2003/06/02");
 script_set_attribute(attribute:"vuln_publication_date", value: "2003/06/02");
 script_cvs_date("Date: 2018/11/15 20:50:22");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_family(english:"FTP");
 
 script_copyright(english:"This script is Copyright (C) 2003-2018 and is owned by Tenable, Inc. or an Affiliate thereof.");

 script_dependencies("ftpserver_detect_type_nd_version.nasl", "ftp_anonymous.nasl");
 script_require_keys("ftp/login");
 script_require_ports("Services/ftp", 21);

 exit(0);
}

include("audit.inc");
include("ftp_func.inc");

port = get_ftp_port(default: 21);
banner = get_ftp_banner(port:port);
if (!banner || "Crob FTP" >!< banner ) audit(AUDIT_NO_BANNER,port);

soc = open_sock_tcp(port);
if (! soc) audit(AUDIT_SOCK_FAIL,port);

ftp_debug(str:"custom banner");
r = ftp_recv_line(socket:soc);
if ( "Crob FTP" >!< r ) audit(AUDIT_NOT_DETECT,"Crob FTP Server",port);

send(socket:soc, data:'USER %d\r\n');
r = ftp_recv_line(socket:soc);
ftp_close(socket:soc);
if(egrep(pattern:"^331.* for [0-9]+", string:r))
{
  security_hole(port);
  exit(0);
}
audit(AUDIT_LISTEN_NOT_VULN,"Crob FTP Server",port);
