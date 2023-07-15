#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(16094);
 script_cve_id("CVE-2004-1428");
 script_bugtraq_id(12139);
 script_version("1.24");
 
 script_name(english:"ArGoSoft FTP Server USER Command Account Enumeration");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote FTP server is vulnerable to an information disclosure
attack." );
 script_set_attribute(attribute:"description", value:
"The remote host is running the ArGoSoft FTP Server. 

The remote version of this software returns different error messages
when a user attempts to log in using a nonexistent username or a bad
password. 

An attacker may exploit this flaw to launch a dictionary attack
against the remote host in order to obtain a list of valid user names." );
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?501c2e30" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to ArGoSoft FTP 1.4.2.2 or newer." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");
 script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
 script_set_attribute(attribute:"cvss_score_source", value:"CVE-2004-1428");
 script_set_attribute(attribute:"cvss_score_rationale", value:"score from a more in depth analysis done by Tenable");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");
 script_set_attribute(attribute:"plugin_publication_date", value: "2005/01/03");
 script_set_attribute(attribute:"vuln_publication_date", value: "2004/10/27");
 script_cvs_date("Date: 2018/11/05 14:12:07");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

 
 summary["english"] = "Checks the error message of the remote FTP server";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2005-2018 and is owned by Tenable, Inc. or an Affiliate thereof.");
 script_family(english:"FTP");
 script_dependencies("ftpserver_detect_type_nd_version.nasl");
 script_require_ports("Services/ftp", 21);
 exit(0);
}

# Check starts here

include("global_settings.inc");
include("audit.inc");
include("ftp_func.inc");

port = get_ftp_port(default: 21);
banner = get_ftp_banner(port:port);
if ( !banner ) audit(AUDIT_NO_BANNER,port);
if ( "ArGoSoft" >!< banner ) audit(AUDIT_NOT_DETECT,"ArGoSoft",port);

soc = open_sock_tcp(port);
if ( ! soc ) audit(AUDIT_SOCK_FAIL,port);

ftp_debug(str:"custom");
banner = ftp_recv_line(socket:soc);
if ( !banner ) audit(AUDIT_NO_BANNER,port);
if ( "ArGoSoft" >!< banner ) audit(AUDIT_NOT_DETECT,"ArGoSoft",port);

send(socket:soc, data:'USER nessus' + rand() + rand() + rand() + '\r\n');
r = ftp_recv_line(socket:soc);
ftp_close(socket:soc);
if ( pgrep(string:r, pattern:"^530 User .* does not exist", icase:TRUE) )
{
  security_warning(port);
  exit(0);
}
audit(AUDIT_LISTEN_NOT_VULN,"ArGoSoft",port);
