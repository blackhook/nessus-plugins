#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(42411);
 script_version("1.12");

 script_cve_id("CVE-1999-0519", "CVE-1999-0520");
 script_bugtraq_id(8026);

 script_name(english:"Microsoft Windows SMB Shares Unprivileged Access");
 script_summary(english:"Reports up to 100 remote accessible shares");
 
 script_set_attribute(attribute:"synopsis", value:
"It is possible to access a network share." );
 script_set_attribute(attribute:"description", value:
"The remote host has one or more Windows shares that can be accessed through
the network with the given credentials. 

Depending on the share rights, it may allow an attacker to read/write
confidential data." );
 script_set_attribute(attribute:"solution", value:
"To restrict access under Windows, open Explorer, right click on
each share, go to the 'Sharing' tab, and click on 'Permissions'." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_attribute(attribute:"cvss_score_source", value:"CVE-1999-0520");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");
 script_set_attribute(attribute:"plugin_publication_date", value:"2009/11/06");
 script_set_attribute(attribute:"vuln_publication_date", value: "1999/07/14");
 script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/07");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
 script_end_attributes();
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009-2022 Tenable Network Security, Inc.");
 script_family(english:"Windows");
 
 script_dependencies("smb_accessible_shares.nasl");
 script_require_keys("/tmp/10396/report", "/tmp/10396/port");
 exit(0);
}

rep = get_kb_item("/tmp/10396/report");
port = get_kb_item("/tmp/10396/port");
if (port && rep) security_hole(port: port, extra: rep);
