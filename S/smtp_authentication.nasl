#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(54580);
  script_version("1.7");
  script_cvs_date("Date: 2019/03/05 11:48:05");

  script_name(english:"SMTP Authentication Methods");
  script_summary(english:"Checks which authentication methods are supported.");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote mail server supports authentication."
  );
  script_set_attribute(
    attribute:"description",
    value:"The remote SMTP server advertises that it supports authentication."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://tools.ietf.org/html/rfc4422"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://tools.ietf.org/html/rfc4954"
  );
  script_set_attribute(
    attribute:"solution",
    value:
"Review the list of methods and whether they're available over an
encrypted channel."
  );
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2011/05/19");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"SMTP problems");

  script_copyright(english:"This script is Copyright (C) 2011-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("smtpserver_detect.nasl", "smtp_starttls.nasl");
  script_require_ports("Services/smtp", 25);

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("smtp_func.inc");

global_var methods;

function get_methods(port, starttls)
{
  local_var auth, auths, enc, encaps, line, lines, matches, result, sock;

  # Connect to the service.
  sock = smtp_open(port:port);
  if (!sock) exit(1, "Failed to open socket on port " + port + ".");

  # Negotiate a StartTLS connection if supported.
  if (starttls)
  {
    var tmp_sock;
    # smtp_starttls does not close sock when it fails, returning NULL
    # this can cause a socket leak.
    tmp_sock = smtp_starttls(socket:sock, encaps:ENCAPS_TLSv1, dont_read_banner:TRUE);
    if (!tmp_sock)
    {
      close(sock);
      return NULL;
    } else {
      sock = tmp_sock;
      tmp_sock = NULL;
    }
  }

  # Get the service's capabilities.
  send(socket:sock, data:'EHLO nessus\r\n');
  lines = smtp_recv_line(socket:sock, code:250);
  if (isnull(lines))
    exit(1, "The SMTP server on port " + port + " didn't respond to our EHLO command.");

  close(sock);

  # Parse out the authentication methods supported.
  line = pgrep(string:lines, pattern:"^250[- ]AUTH ");
  if (line == "") return NULL;
  line = substr(chomp(line), 9);
  auths = split(line, sep:" ", keep:FALSE);

  # Decide whether this is an encrypted connection.
  encaps = get_kb_item("Transports/TCP/" + port);

  # enc is 1 if encryption is available, 0 otherwise
  enc = int(starttls || (encaps >= ENCAPS_SSLv2 && encaps <= ENCAPS_TLSv1));

  # Save the authentication methods to the KB.
  foreach auth (sort(auths))
  {
    if (enc) set_kb_item(name:"smtp/" + port + "/auth_tls", value:auth);
    else set_kb_item(name:"smtp/" + port + "/auth", value:auth);
    # add auth to the relevant list
    methods[enc] = make_list(methods[enc], auth);
  }
  return NULL;
}

port = get_service(svc:"smtp", default:25, exit_on_fail:TRUE);

# Create data structure to store all the authentication methods that
# this port supports.
methods = make_array();
methods[FALSE] = make_list();
methods[TRUE] = make_list();

# Enumerate all the authentication methods that the port supports,
# both before and after StartTLS.
get_methods(port:port, starttls:FALSE);
get_methods(port:port, starttls:TRUE);

report = "";
foreach key (make_list(FALSE, TRUE))
{
  if (max_index(methods[key]) == 0) continue;

  if (key) with = "with";
  else with = "without";

  tmp_report =
    '\nThe following authentication methods are advertised by the SMTP' +
    '\nserver ' + with + ' encryption : ' +
    '\n';

  foreach method (methods[key])
    tmp_report += '  ' + method + '\n';

  if (!key && get_kb_item("Settings/PCI_DSS"))
  {
    set_kb_item(name:"PCI/ClearTextCreds/" + port, value:tmp_report);
  }

  report += tmp_report;
}

if (report == "")
  exit(0, "The SMTP server on port " + port + " doesn't appear to support the AUTH command.");

if (report_verbosity > 0)
  security_note(port:port, extra:report);
else
  security_note(port);
