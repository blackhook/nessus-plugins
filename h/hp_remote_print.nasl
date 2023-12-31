#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(10104);
  script_version("1.31");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-1999-1062");

  script_name(english:"HP LaserJet Direct Print Filter Bypass");

  script_set_attribute(attribute:"synopsis", value:
"Print filters on the remote printer can be bypassed.");
  script_set_attribute(attribute:"description", value:
"By connecting to this port directly, a remote attacker can send
Postscript directly to the remote printer, bypassing lpd and page
accounting. 

This is a threat, because an attacker may connect to this printer,
force it to print pages of garbage, and make it run out of paper.  If
this printer is used to print security logs, then this will be a
problem.");
  script_set_attribute(attribute:"see_also", value:"https://seclists.org/bugtraq/1997/Oct/32");
  script_set_attribute(attribute:"solution", value:
"Filter incoming traffic to this port.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_set_attribute(attribute:"vuln_publication_date", value:"1997/10/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"1999/06/22");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:hp:jetdirect");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 1999-2022 Tenable Network Security, Inc.");

  script_dependencies("find_service1.nasl", "passwordless_hp_printer.nasl");
  script_require_keys("devices/hp_printer");
  script_require_ports(9099);

  exit(0);
}

#
# The script code starts here
#

hp = get_kb_item("devices/hp_printer");
if(hp)
{
 if(get_port_state(9099))
 {
  soc = open_sock_tcp(9099);
  if(soc){
  	security_warning(9099);
  	close(soc);
	}
 }
 if(get_port_state(9100))
 {
  soc = open_sock_tcp(9100);
  if(soc){
  	security_warning(9100);
	close(soc);
	}
 }
}
