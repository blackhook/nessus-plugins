#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(10653);
 script_bugtraq_id(2564);
 script_version ("1.24");
 script_name(english:"Solaris FTP Daemon CWD Command Account Enumeration");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote FTP server is susceptible to an account enumeration attack." );
 script_set_attribute(attribute:"description", value:
"It is possible to determine the existence of a user on the remote
system by issuing the command CWD ~<username>, even before logging in.
An attacker can exploit this flaw to determine the existence of known
vulnerable accounts." );
 script_set_attribute(attribute:"solution", value:
"There is no known solution at this time." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:U/RC:C");
 script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");
 script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:U/RC:C");
 script_set_attribute(attribute:"cvss_score_source", value:"manual");
 script_set_attribute(attribute:"cvss_score_rationale", value:"score from a more in depth analysis done by Tenable");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");
 
 script_set_attribute(attribute:"plugin_publication_date", value: "2001/04/16");
 script_set_attribute(attribute:"vuln_publication_date", value: "2001/04/11");
 script_cvs_date("Date: 2018/11/05 14:12:07");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

 
 script_summary(english:"CWD ~root before logging in");
 
 script_category(ACT_ATTACK);
 
 script_copyright(english: "This script is Copyright (C) 2001-2018 and is owned by Tenable, Inc. or an Affiliate thereof.");
 script_family(english:"FTP");
 script_dependencies("ftpserver_detect_type_nd_version.nasl");
 script_require_ports("Services/ftp", 21);
 exit(0);
}

#
# The script code starts here
#

include("audit.inc");
include("ftp_func.inc");

port = get_ftp_port(default: 21);

banner = get_ftp_banner(port:port);
if (!banner) audit(AUDIT_NO_BANNER, port);
if ("SunOS" >!< banner ) audit(AUDIT_NOT_DETECT,"Solaris FTP",port);

soc = open_sock_tcp(port);
if (! soc) audit(AUDIT_SOCK_FAIL,port);
ftp_debug(str:"custom");
data = ('CWD ~nonexistinguser\r\n');
send(socket:soc, data:data);
a = ftp_recv_line(socket:soc);
ftp_close(socket:soc);
if(egrep(pattern:"^550 Unknown user name after ~", string:a))
{
  security_warning(port);
  exit(0);
}
audit(AUDIT_LISTEN_NOT_VULN,"Solaris FTP",port);
