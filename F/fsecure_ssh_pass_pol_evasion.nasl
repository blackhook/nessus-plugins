#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if(description)
{
  script_id(12099);
  script_bugtraq_id(9824);
  script_version ("1.13");

  script_name(english:"F-Secure SSH Password Authentication Policy Evasion");
  script_summary(english:"F-Secure SSH version");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote SSH server has a security bypass vulnerability."
  );
  script_set_attribute( attribute:"description",  value:
"According to its banner, the version of F-Secure SSH running on the
remote host allows a user to log in using a password, even though the
server policy disallows it.  An attacker could exploit this flaw to
run a dictionary attack against the SSH server."  );
  script_set_attribute(
    attribute:"solution", 
    value:"Upgrade to F-Secure SSH 3.1.0 build 9 or later."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:W/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
 script_set_attribute(attribute:"plugin_publication_date", value: "2004/03/14");
 script_cvs_date("Date: 2018/12/05 20:31:22");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe",value:"cpe:/a:f-secure:f-secure_ssh_server");
  script_end_attributes();

  script_category(ACT_GATHER_INFO); 
  script_family(english:"Gain a shell remotely");

  script_copyright(english:"This script is Copyright (C) 2004-2018 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_require_ports("Services/ssh", 22);
  script_dependencie("ssh_detect.nasl");

  exit(0);
}

#
# The script code starts here
#

port = get_kb_item("Services/ssh");
if (!port) port = 22;

banner = get_kb_item( "SSH/banner/" + port );
if(!banner) exit(0);

#
# SSH-2.0-3.2.0 F-Secure SSH Windows NT Server
# versions up to 3.1.0 affected
#
if(ereg(pattern:"^SSH-2.0-([12]\..*|3\.[01]\..*) F-Secure SSH", string:banner, icase:TRUE))
{ 
  security_warning(port);
}
