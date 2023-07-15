#TRUSTED 32e6b1466584ed6fa3fd97c74c9d1091d685298b1f8647212fe4f97a07d313d150a7f793c99a2c60405327c98fc8742cbdd0fcca24f6423b4a675d6bbdd34780efa9ac4317cfe5a5683a290952f6d7d93c9c761c55ce25353aa21eb1fe8177c2a1f22884f62bd18eaa8358720f5c11a7c927fc016e7d868cc7fa19f8dc96e2fb8f04ac967e5eb6d978aa60c60b49ac4d00b569cc62320e2a9e2f78ee572cd1e6e9ca461684624f48630b80cfe37a52e1d3caacfa66b69765483a433a9b3f51a4f28da163025bdf518d917bdca932962b959a2efa2ceabaa88227909f342a6632d3f1c3fc872de4d8ee808ebf25cef6ce7f4221ed5c092d9f7352c2fb7bd7b4bd13ffcc558d9d44ea202085861951bda4dc8e6778a3fce56cc6eb930208341cfe3be894d01582912f73557863f6a1ede23d93a6ffcbf17c052ec96b698c0bdc42f0c910d743f4b4bc5a18b82660d040a2ef4d8923c6b7aa8c7839c7d1095d09bd664b213c5641f18a71ee554f3815ae365c1418720e1c2ad5185f8f352dd3d4d5e30e56382d94d8f2f729ec21547d1c7894ef339b04d829ff16479b4061b7d08f7c5586386c5bff3d809fdce87cc3900420c651bc29570767e4faa26c058742a022c1fc177733c049d4ea37e3642395d32a1a946be3ffd6d9ba2b50e5e951e5f4732520017561f1b7ba57a36a458e19f4adf5507f34c90712ff9ced515afd079b
###
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(11677);
 script_bugtraq_id(7674);
 script_cve_id("CVE-2003-0392");
 script_version ("1.31");

 script_name(english:"ST FTP Service Arbitrary File/Directory Access");

 script_set_attribute(attribute:"synopsis", value:
"Arbitrary files may be read on the remote hosts." );
 script_set_attribute(attribute:"description", value:
"The remote FTP server is vulnerable to a flaw that allows users
to access files that are outside the FTP server root.

An attacker may break out of his FTP jail by issuing the command :

CWD C:" );
 script_set_attribute(attribute:"see_also", value:"https://www.securityfocus.com/archive/1/322496" );
 script_set_attribute(attribute:"solution", value:
"Contact your vendor for a patch." );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:P");
 script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2003-0392");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");

 script_set_attribute(attribute:"plugin_publication_date", value: "2003/06/02");
 script_set_attribute(attribute:"vuln_publication_date", value: "2003/05/24");
 script_cvs_date("Date: 2019/05/10 20:04:30");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_set_attribute(attribute:"cpe",value:"cpe:/a:st:ftp_service");
 script_end_attributes();


 summary["english"] = "Attempts to break out of the FTP root";
 script_summary(english:summary["english"]);

 script_category(ACT_GATHER_INFO);

  script_copyright(english:"This script is Copyright (C) 2003-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");
 script_family(english:"FTP");
 script_dependencies("ftpserver_detect_type_nd_version.nasl", "ftp_anonymous.nasl");
 script_require_keys("ftp/login");
 script_exclude_keys("global_settings/supplied_logins_only");
 script_require_ports("Services/ftp", 21);
 exit(0);
}

include("global_settings.inc");
include("ftp_func.inc");

if (supplied_logins_only) audit(AUDIT_SUPPLIED_LOGINS_ONLY);

global_var port, soc;

function dir()
{
 local_var ls, p, r, result, soc2;

 p = ftp_pasv(socket:soc);
 if (!p) exit(1, "Cannot get FTP passive port from control port "+port+".");
 soc2 = open_sock_tcp(p, transport:get_port_transport(port));
 if(!soc2)return(0);
 ls = 'LIST .\r\n';
 send(socket:soc, data:ls);
 r = ftp_recv_line(socket:soc);
 if(egrep(pattern:"^150 ", string:r))
 {
  result = ftp_recv_listing(socket:soc2);
  close(soc2);
  r = ftp_recv_line(socket:soc);
  return(result);
 }
 return(0);
}


#
# The script code starts here
#

port = get_ftp_port(default: 21);

 login = get_kb_item("ftp/login");
 pass = get_kb_item("ftp/password");

 soc = ftp_open_and_authenticate( user:login, pass:pass, port:port );
 if(soc)
 {
 send(socket:soc, data: 'CWD /\r\n');
 ftp_recv_line(socket:soc);
 listing2 = dir();
 if(!listing2)exit(1, 'Cannot read FTP answer from port '+port+'.');

 send(socket:soc, data: 'CWD /\r\n');
 ftp_recv_line(socket:soc);
 listing1 = dir();
 if(!listing1)exit(1, 'Cannot read FTP answer from port '+port+'.');
 if (listing1 != listing2)
  exit(1, "Different answers for the same command on port "+port+"; this server cannot be tested reliably.");

 send(socket:soc, data: 'CWD C:\r\n');
 ftp_recv_line(socket:soc);
 listing2 = dir();
 if(!listing2)exit(1, 'Cannot read FTP answer from port '+port+'.');

 close(soc);

 if(listing1 != listing2)
   security_warning(port);
 }
