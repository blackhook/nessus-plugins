#
# (C) Tenable Network Security, Inc.
#

# Script audit and contributions from Carmichael Security
#      Erik Anderson <eanders@carmichaelsecurity.com> (nb: domain no longer exists)
#      Fixed broken link
#


include("compat.inc");

if(description)
{
 script_id(10973);
 script_version("1.22");
 script_cve_id("CVE-1999-0162");
 script_bugtraq_id(315);

 script_name(english:"Cisco IOS established Keyword ACL Bypass (CSCdi34061)");

 script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch." );
 script_set_attribute(attribute:"description", value:
"The remote device seems to be vulnerable to a flaw in IOS when
the keyword 'established' is being used in the ACLs.

This bug can, under very specific circumstances and only with
certain IP host implementations, allow unauthorized packets to
circumvent a filtering router.

This vulnerability is documented as Cisco Bug ID CSCdi34061." );
 script_set_attribute(attribute:"solution", value:
"http://www.nessus.org/u?096cac5c" );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");

 script_set_attribute(attribute:"plugin_publication_date", value: "2002/06/05");
 script_cvs_date("Date: 2018/06/27 18:42:25");
 script_set_attribute(attribute:"vuln_publication_date", value: "1992/12/10");
 script_set_attribute(attribute:"plugin_type", value:"local");
 script_set_attribute(attribute:"cpe", value: "cpe:/o:cisco:ios");
 script_end_attributes();

 script_summary(english:"Uses SNMP to determine if a flaw is present");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is (C) 2002-2018 Tenable Network Security, Inc.");
 script_family(english:"CISCO");
 script_dependencie("snmp_sysDesc.nasl", "snmp_cisco_type.nasl");
 script_require_keys("SNMP/community", "SNMP/sysDesc", "CISCO/model");
 exit(0);
}

# The code starts here

ok=0;
os = get_kb_item("SNMP/sysDesc"); if(!os)exit(0);
hardware = get_kb_item("CISCO/model"); if(!hardware)exit(0);




# Check for the required operating system...
#----------------------------------------------------------------
# Is this IOS ?
if(!egrep(pattern:".*(Internetwork Operating|IOS).*", string:os))exit(0);
# 10.0
if(egrep(string:os, pattern:"(10\.0\([0-9]\)|10\.0),"))ok=1;

# 10.2
if(egrep(string:os, pattern:"(10\.2\([0-5]\)|10\.2),"))ok=1;

# 10.3
if(egrep(string:os, pattern:"(10\.3\([0-2]\)|10\.3),"))ok=1;


#----------------------------------------------

if(ok)security_warning(port:161, proto:"udp");
