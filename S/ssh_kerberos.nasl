#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(10472);
 script_version ("1.29");
 script_cve_id("CVE-2000-0575");
 script_bugtraq_id(1426);
 
 script_name(english:"SSH with Kerberos NFS Share Ticket Disclosure");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote SSH server does not properly protect the kerberos tickets of
the users." );
 script_set_attribute(attribute:"description", value:
"The remote host is running a version of SSH which is older than (or as old as) 
version 1.2.27.

There is a flaw in the remote version of this software which allows an attacker
to eavesdrop the kerberos tickets of legitimate users of this service, as sshd 
will set their environment variable KRB5CCNAME to 'none' when they log in. 
As a result, kerberos tickets will be stored in the current working directory 
of the user, as 'none'.

In certain cases, this may allow an attacker to obtain the tickets." );
 script_set_attribute(attribute:"solution", value:
"Upgrade to the newest version of SSH." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:P/I:N/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");
	
 script_set_attribute(attribute:"plugin_publication_date", value: "2000/07/16");
 script_set_attribute(attribute:"vuln_publication_date", value: "2000/06/30");
 script_cvs_date("Date: 2018/08/03 11:35:08");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

 
 script_summary(english:"Checks for the remote SSH version");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2000-2018 Tenable Network Security, Inc.");
 script_family(english:"Misc.");
 script_dependencie("ssh_detect.nasl");
 script_require_ports("Services/ssh", 22);
 exit(0);
}

#
# The script code starts here
#

include("backport.inc");
port = get_kb_item("Services/ssh");
if(!port)port = 22;


kb = get_kb_item("SSH/supportedauth/" + port );
if ( ! kb || "kerberos" >!< kb ) exit(0);

banner = get_kb_item("SSH/banner/" + port );
if ( ! banner ) exit(0);

banner = get_backport_banner(banner:banner);


if(ereg(string:banner,
  	pattern:"ssh-.*-1\.([0-1]\..*|2\.([0-1]..*|2[0-7]))[^0-9]*",
	icase:TRUE))security_note(port);
