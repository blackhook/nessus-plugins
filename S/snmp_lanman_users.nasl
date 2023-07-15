#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
	script_id(10546);
	script_version ("1.41");
	script_cvs_date("Date: 2019/10/04 16:48:26");

	script_cve_id ("CVE-1999-0499");

	script_name(english:"Microsoft Windows LAN Manager SNMP LanMan Users Disclosure");

	script_set_attribute(attribute:"synopsis", value:
	"The list of LanMan users of the remote host can be obtained via SNMP." );
	script_set_attribute(attribute:"description", value:
	"It is possible to obtain the list of LanMan users on the remote host
	by sending SNMP requests with the OID 1.3.6.1.4.1.77.1.2.25.1.1

	An attacker may use this information to gain more knowledge about the
	target host." );
	script_set_attribute(attribute:"solution", value:
	"Disable the SNMP service on the remote host if you do not use it, or
	filter incoming UDP packets going to this port." );
	script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
	script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");
	script_set_attribute(attribute:"cvss_score_source", value:"manual");
	script_set_attribute(attribute:"cvss_score_rationale", value:"Tenable score for Information Disclosure");

	script_set_attribute(attribute:"plugin_publication_date", value: "2000/11/10");
	script_set_attribute(attribute:"plugin_type", value:"remote");
	script_end_attributes();

	script_summary(english:"Enumerates users via SNMP");
	script_category(ACT_GATHER_INFO);
	script_copyright(english:"This script is Copyright (C) 2005-2018 and is owned by Tenable, Inc. or an Affiliate thereof.");
	script_family(english:"SNMP");
	script_dependencies("snmp_settings.nasl", "find_service2.nasl");
	script_require_keys("SNMP/community");
	exit(0);
}

include ("snmp_func.inc");
include ("misc_func.inc");
include ("data_protection.inc");

community = get_kb_item("SNMP/community");
if(!community)exit(0);

port = get_kb_item("SNMP/port");
if(!port)port = 161;
if (! get_udp_port_state(port)) exit(0, "UDP port "+port+" is not open.");

soc = open_sock_udp(port);
if (!soc)
  exit (0);

users = scan_snmp_string (socket:soc, community:community, oid:"1.3.6.1.4.1.77.1.2.25.1.1");

if(strlen(users))
{
 users = data_protection::sanitize_user_enum(users:users);
 security_warning(port:port, extra: users, protocol:"udp");
}
