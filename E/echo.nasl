#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(10061);
 script_version ("1.46");
 script_set_attribute(attribute:"plugin_modification_date", value:"2020/06/12");
 script_cve_id("CVE-1999-0103", "CVE-1999-0635");

 script_name(english:"Echo Service Detection");

 script_set_attribute(attribute:"synopsis", value:
"An echo service is running on the remote host." );
 script_set_attribute(attribute:"description", value:
"The remote host is running the 'echo' service. This service 
echoes any data which is sent to it.

This service is unused these days, so it is strongly advised that
you disable it, as it may be used by attackers to set up denial of
services attacks against this host." );
 script_set_attribute(attribute:"solution", value:
"Below are some examples of how to disable the echo service on some common
platforms, however many services can exhibit this behavior and the list below
is not exhaustive. 

Consult vendor documentation for the service exhibiting the echo behavior
for more information.

- Under Unix systems, comment out the 'echo' line in /etc/inetd.conf
  and restart the inetd process.

- Under Ubuntu systems, comment out the 'echo' line in 
   /etc/systemd/system.conf and retart the systemd service.

- Under Windows systems, set the following registry key to 0 :
  HKLM\System\CurrentControlSet\Services\SimpTCP\Parameters\EnableTcpEcho
  HKLM\System\CurrentControlSet\Services\SimpTCP\Parameters\EnableUdpEcho

Then launch cmd.exe and type :

   net stop simptcp
   net start simptcp

To restart the service." );

 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
 script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H");
 script_set_attribute(attribute:"cvss_score_source", value:"CVE-1999-0103");

 script_set_attribute(attribute:"plugin_publication_date", value: "1999/06/22");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_summary(english:"Checks if the 'echo' port is open");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 1999-2020 and is owned by Tenable, Inc. or an Affiliate thereof.");
 script_family(english:"Service detection");
 script_dependencie("find_service1.nasl");
 exit(0);
}


include("global_settings.inc");
include("misc_func.inc");

pattern = "Harmless Nessus echo test";

port = get_kb_item("Services/echo");
if(!port)port = 7;
if(get_port_state(port))
{
 soc = open_sock_tcp(port);
 if(soc)
 {
  data = string(pattern, "\r\n");
  send(socket:soc, data:data);
  res = recv_line(socket:soc, length:1024);
  if(data == res)
   {
   security_report_v4(port:port, severity:SECURITY_WARNING);
   register_service(port:port, proto:"echo");
   }
  close(soc);
  }
}

if(get_udp_port_state(port))
{
 soc = open_sock_udp(port);
 if(soc)
 {
  data = string(pattern, "\r\n");
  send(socket:soc, data:data);
  res2 = recv(socket:soc, length:1024);
  if(res2)
  {
    if(data ==  res2)security_report_v4(port:port, proto:"udp", severity:SECURITY_WARNING);
  }
  close(soc);
 }
}

