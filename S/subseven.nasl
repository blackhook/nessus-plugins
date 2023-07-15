#
# (C) Tenable Network Security, Inc.
#
# Added some extra checks. Axel Nennker axel@nennker.de 20020301


include("compat.inc");

if(description)
{
 script_id(10409);
 script_version ("1.26");
 script_set_attribute(attribute:"plugin_modification_date", value:"2020/04/27");

 script_name(english: "SubSeven Trojan Detection");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote host has been compromised." );
 script_set_attribute(attribute:"description", value:
"This host seems to be running SubSeven on this port.
SubSeven is a Trojan Horse which allows an intruder to take the control 
of the remote computer.

An attacker may use it to steal your passwords, modify your data, and 
preventing you from working properly." );
 script_set_attribute(attribute:"solution", value:
"Remove any instances of the SubSeven Trojan and conduct a forensic
examination to determine how it was installed as well as whether
other unauthorized changes were made." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");


 script_set_attribute(attribute:"plugin_publication_date", value: "2000/05/15");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

 script_summary(english: "Determines the presence of SubSeven");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2000-2020 Tenable Network Security, Inc.");
 script_family(english: "Backdoors");
 script_dependencie("find_service2.nasl");
 script_require_ports("Services/subseven");
 exit(0);
}

#
# The script code starts here
#

port = get_kb_item("Services/subseven");
if (port) security_hole(port);
