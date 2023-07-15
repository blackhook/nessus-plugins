#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(11364);
 script_version("1.20");
 script_cvs_date("Date: 2018/07/24 17:29:25");

 script_cve_id("CVE-2003-1076");
 script_bugtraq_id(7033);

 script_name(english:"Solaris sendmail .forward Local Privilege Escalation");
 script_summary(english:"Checks the version number of sendmail");

 script_set_attribute(attribute:"synopsis", value:"The remote server is vulnerable to a privilege escalation attack.");
 script_set_attribute(attribute:"description", value:
"The remote sendmail server, according to its version number, may be
vulnerable to a local privilege escalation attack when using forward
files. 

*** Sun did not increase the version number of their sendmail
*** when patching Solaris 7 and 8, so this might be a false
*** positive on these platforms.

An attacker may set up a special .forward file in his home and send a
mail to himself, which will trick sendmail and will allow him to
execute arbitrary commands with root privileges.");
 script_set_attribute(attribute:"solution", value: "Upgrade to the latest version of sendmail");
 script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");

 script_set_attribute(attribute:"vuln_publication_date", value:"2003/03/06");
 script_set_attribute(attribute:"plugin_publication_date", value:"2003/03/12");

 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:sendmail:sendmail");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2003-2018 and is owned by Tenable, Inc. or an Affiliate thereof.");
 script_family(english:"SMTP problems");

 script_dependencie("smtpserver_detect.nasl", "os_fingerprint.nasl");
 script_require_ports("Services/smtp", 25);

 script_require_keys("SMTP/sendmail");
 exit(0);
}

#
# The script code starts here
#

include("smtp_func.inc");

port = get_kb_item("Services/smtp");
if(!port) port = 25;

banner = get_smtp_banner(port:port);
if(banner)
{
  os = get_kb_item("Host/OS");

  if(os && (("Solaris 2.6" >< os)   ||
     ("Solaris 7" >< os)   ||
     ("Solaris 8" >< os)))
  { 
     if(egrep(pattern:".*Sendmail ((5\.79.*|5\.[89].*|[67]\..*|8\.[0-9]\..*|8\.10\..*|8\.11\.[0-5])\+Sun/|SMI-[0-8]\.).*", string:banner, icase:TRUE))
 	security_hole(port);
  }
  else if(!os || "Solaris 9" >< os)
  {
   if(egrep(pattern:".*Sendmail (5\.79.*|5\.[89].*|[67]\..*|8\.[0-9]\..*|8\.1[0-1]\..*|8\.12\.[0-7])\+Sun/.*", string:banner, icase:TRUE))
 	security_hole(port);
  }
}
