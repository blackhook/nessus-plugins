#
# (C) Tenable Network Security, Inc.
#


if ( NASL_LEVEL < 4000 ) exit(0);


include("compat.inc");


if (description)
{
  script_id(52611);
  script_version("1.21");
  script_cvs_date("Date: 2019/03/06 18:38:55");

  script_cve_id(
    "CVE-2011-0411",
    "CVE-2011-1430",
    "CVE-2011-1431",
    "CVE-2011-1432",
    "CVE-2011-1506",
    "CVE-2011-2165"
  );
  script_bugtraq_id(46767);
  script_xref(name:"CERT", value:"555316");

  script_name(english:"SMTP Service STARTTLS Plaintext Command Injection");
  script_summary(english:"Tries to inject a command along with STARTTLS");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote mail service allows plaintext command injection while 
negotiating an encrypted communications channel."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The remote SMTP service contains a software flaw in its STARTTLS
implementation that could allow a remote, unauthenticated attacker to
inject commands during the plaintext protocol phase that will be
executed during the ciphertext protocol phase. 

Successful exploitation could allow an attacker to steal a victim's
email or associated SASL (Simple Authentication and Security Layer)
credentials."
  );
  script_set_attribute(
    attribute:"see_also", 
    value:"https://tools.ietf.org/html/rfc2487"
  );
  script_set_attribute(
    attribute:"see_also", 
    value:"https://www.securityfocus.com/archive/1/516901/30/0/threaded"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Contact the vendor to see if an update is available."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/03/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/03/10");

  script_set_attribute(attribute:"plugin_type", value:"remote");

  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"SMTP problems");

  script_copyright(english:"This script is Copyright (C) 2011-2019 Tenable Network Security, Inc.");

  script_dependencies("smtp_starttls.nasl");
  script_require_ports("Services/smtp", 25);

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("smtp_func.inc");


port = get_service(svc:"smtp", default:25, exit_on_fail:TRUE);
if (!get_kb_item("smtp/"+port+"/starttls"))
{
  if (get_kb_item("smtp/"+port+"/starttls_tested"))
    exit(0, "The SMTP server on port "+port+" does not support STARTTLS.");

  encaps = get_kb_item("Transports/TCP/"+port);
  if (encaps && encaps > ENCAPS_IP) 
    exit(0, "The SMTP server on port "+port+" always encrypts traffic.");
}


soc = smtp_open(port:port, helo:compat::this_host());
if (!soc) exit(1, "Can't open socket on port "+port+".");


# Send the exploit.
c = 'STARTTLS\r\nRSET\r\n';
send(socket:soc, data:c);
s1 = smtp_recv_line(socket:soc);
if (strlen(s1)) s1 = chomp(s1);

if (strlen(s1) < 4)
{
  smtp_close(socket:soc);

  if (strlen(s1)) errmsg = "The SMTP server on port "+port+" sent an invalid response (" + s1 + ").";
  else errmsg = "The SMTP server on port "+port+" failed to respond to a 'STARTTLS' command.";
  exit(1, errmsg);
}
if (substr(s1, 0, 2) != "220") exit(1, "The SMTP server on port "+port+" did not accept the command (", s1, ").");

# nb: finally, we need to make sure the second command worked.
soc = socket_negotiate_ssl(socket:soc, transport:ENCAPS_TLSv1);
if (!soc) exit(1, "Failed to negotiate a TLS connection with the SMTP server on port "+port+".");
s2 = smtp_recv_line(socket:soc);
if (strlen(s2)) s2 = chomp(s2);

smtp_close(socket:soc);

if (strlen(s2) == 0) exit(0, "The SMTP server on port "+port+" does not appear to be affected.");
else
{
  if (strlen(s2) >= 3 && substr(s2, 0, 2) == "250")
  {
    if (report_verbosity > 0)
    {
      report = 
        '\n' + 'Nessus sent the following two commands in a single packet :' +
        '\n' +
        '\n' + '  ' + str_replace(find:'\r\n', replace:'\\r\\n', string:c) + 
        '\n' +
        '\n' + 'And the server sent the following two responses :' +
        '\n' +
        '\n' + '  ' + s1 +
        '\n' + '  ' + s2 + '\n';
      security_warning(port:port, extra:report);
    }
    else security_warning(port);
    exit(0);
  }
  else exit(0, "The SMTP server on port "+port+" does not appear to be affected as it responded '" + s2 + "'.");
}
