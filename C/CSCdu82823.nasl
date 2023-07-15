#
# (C) Tenable Network Security, Inc.
#

# Thanks to Nicolas FISCHBACH (nico@securite.org) for his help
#
# Ref:  http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20020903-vpn3k-vulnerability


include("compat.inc");

if(description)
{
 script_id(11290);
 script_version("1.16");
 script_cvs_date("Date: 2019/04/04 10:49:02");

 script_cve_id("CVE-2001-0427");
 script_bugtraq_id(88960);
 script_xref(name:"CISCO-SA", value:"cisco-sa-20020903-vpn3k-vulnerability");
 script_xref(name:"CISCO-BUG-ID", value:"CSCdu82823");

 script_name(english:"Cisco VPN Concentrator Invalid Login DoS (CSCdu82823)");
 script_summary(english:"Uses SNMP to determine if a flaw is present");

 script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch." );
 script_set_attribute(attribute:"description", value:
"The remote VPN concentrator has a bug in its
implementation of telnetd.

This vulnerability is documented as Cisco bug ID CSCdu82823." );
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d2dd6759");
 script_set_attribute(attribute:"solution", value:
"Apply the update or workaround as recommend in the vendory advisory.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:C");
 script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
 script_set_attribute(attribute:"cvss_score_source", value:"CVE-2001-0427");
 script_cwe_id(20);

 script_set_attribute(attribute:"vuln_publication_date", value: "2001/03/29");
 script_set_attribute(attribute:"patch_publication_date", value: "2001/03/29");
 script_set_attribute(attribute:"plugin_publication_date", value: "2003/03/01");

 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_set_attribute(attribute:"cpe", value: "cpe:/o:cisco:ios");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_family(english:"CISCO");

 script_copyright(english:"This script is Copyright (C) 2003-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

 script_dependencies("snmp_sysDesc.nasl");
 script_require_keys("SNMP/community", "SNMP/sysDesc", "CISCO/model");
 script_require_ports(23);

 exit(0);
}

if(!get_port_state(23))exit(0);
soc = open_sock_tcp(23);
if(!soc)exit(0);
else close(soc);

# The code starts here

ok=0;

os = get_kb_item("SNMP/sysDesc"); if(!os)exit(0);



# Is this a VPN3k concentrator ?
if(!egrep(pattern:".*VPN 3000 Concentrator.*", string:os))exit(0);


# < 3.0.4
if(egrep(pattern:".*Version 3\.0\.Rel.*", string:os))ok = 1;
if(egrep(pattern:".*Version 3\.0\.[0-3].*", string:os))ok = 1;

# 2.x.x
if(egrep(pattern:".*Version 2\..*", string:os))ok = 1;


if(ok)security_hole(port:161, proto:"udp");
