#
# This script was written by George A. Theall, <theall@tifaware.com>.
#
# See the Nessus Scripts License for details.
#

# Changes by Tenable:
# - Revised plugin title, output formatting (9/3/09)


include('compat.inc');

if (description) {
  script_id(15855);
  script_version("1.23");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/07/05");

  script_name(english:"POP3 Cleartext Logins Permitted");
  script_summary(english:"Checks if POP3 daemon allows unencrypted cleartext logins");

  script_set_attribute(attribute:"synopsis", value:
"The remote POP3 daemon allows credentials to be transmitted in
cleartext.");
  script_set_attribute(attribute:"description", value:
"The remote host is running a POP3 daemon that allows cleartext logins
over unencrypted connections. An attacker can uncover user names and
passwords by sniffing traffic to the POP3 daemon if a less secure
authentication mechanism (eg, USER command, AUTH PLAIN, AUTH LOGIN) is
used.

Note: This plugin requires paranoid mode, and is prone to false positives.");
  script_set_attribute(attribute:"solution", value:
"Contact your vendor for a fix or encrypt traffic with SSL /
TLS using stunnel.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:P/I:N/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_set_attribute(attribute:"cvss_score_source", value:"manual");
  script_set_attribute(attribute:"cvss_score_rationale", value:"Score based on analysis of potential secuirty issues.");
  script_set_attribute(attribute:"see_also", value:"https://tools.ietf.org/html/rfc2222");
  script_set_attribute(attribute:"see_also", value:"https://tools.ietf.org/html/rfc2595");

  script_set_attribute(attribute:"plugin_publication_date", value:"2004/11/30");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2004-2022 George A. Theall");
  script_family(english:"Misc.");
  script_dependencies("find_service1.nasl", "global_settings.nasl", "logins.nasl");
  script_require_ports("Services/pop3", 110);
  script_require_keys("Settings/ParanoidReport");
  exit(0);
}

include('debug.inc');

# Making paranoid dsue to high possibility of FPs
if (report_paranoia < 2) audit(AUDIT_PARANOID);

# nb: non US ASCII characters in user and password must be
#     represented in UTF-8.
var user = get_kb_item("pop3/login");
var pass = get_kb_item("pop3/password");

var port = get_service(svc:"pop3", default: 110, exit_on_fail: 1);
if (get_kb_item("pop3/"+port+"/false_pop3")) exit(0);

debug_print("checking if POP3 daemon on port ", port, " allows unencrypted cleartext logins.");
# nb: skip it if traffic is encrypted.
var encaps = get_kb_item("Transports/TCP/" + port);
if (encaps > 1) exit(0);

# Establish a connection.
var soc = open_sock_tcp(port);
if (!soc) exit(0);

var s, c, caps, n, done, clrtxt, m, resp;

# Read banner.
s = recv_line(socket:soc, length:1024);
if (!strlen(s)) {
  close(soc);
  exit(0);
}
s = chomp(s);
debug_print("S: '", s, "'.");

# Try to determine server's capabilities.
c = "CAPA";
debug_print("C: '", c, "'.");
send(socket:soc, data:strcat(c, '\r\n'));
caps = "";
s = recv_line(socket:soc, length:1024);
s = chomp(s);
debug_print("S: '", s, "'.");
if (s =~ "^\+OK") {
  n = 0;
  while (s = recv_line(socket:soc, length:1024)) {
    if ( ++n > 1024 ) exit(1, "Remote server is sending too much data");
    s = chomp(s);
    debug_print("S: '", s, "'.");
    if (s =~ "^\.$") break;
    caps = strcat(caps, s, '\n');
  }
}

dbg::detailed_log(lvl:2, msg:'Capabilities:\n' + caps);

# Try to determine if problem exists from server's capabilities;
# otherwise, try to actually log in.
done = 0;
clrtxt = pgrep(string:caps, pattern:"(SASL (PLAIN|LOGIN)|USER)", icase:TRUE);
if (clrtxt) {
  if ( get_kb_item("Settings/PCI_DSS") ) set_kb_item(name:"PCI/ClearTextCreds/" + port,
						value:"The remote POP3 daemon allows credentials to be transmitted in clear text");
  security_report_v4(port:port, extra:'The following cleartext methods are supported :\n' + clrtxt, severity:SECURITY_NOTE);
  done = 1;
}
if (!done && strlen(user) && strlen(pass) ) {
  # nb: there's no way to distinguish between a bad username / password
  #     combination and disabled unencrypted logins. This makes it
  #     important to configure the scan with valid POP3 username /
  #     password info.

  # - try the PLAIN SASL mechanism.
  c = "AUTH PLAIN";
  debug_print("C: '", c, "'.");
  send(socket:soc, data:strcat(c, '\r\n'));
  s = recv_line(socket:soc, length:1024);
  s = chomp(s);
  debug_print("S: '", s, "'.");
  if (s =~ "^\+") {
    c = base64(str:raw_string(0, user, 0, pass));
    debug_print("C: '", c, "'.");
    send(socket:soc, data:strcat(c, '\r\n'));
    n = 0;
    while (s = recv_line(socket:soc, length:1024)) {
      if ( ++n > 1024 ) exit(1, "Remote server is sending too much data");
      s = chomp(s);
      debug_print("S: '", s, "'.");
      m = pregmatch(pattern:"^(\+OK|-ERR) ", string:s, icase:TRUE);
      if (!isnull(m)) {
        resp = m[1];
        break;
      }
      resp = "";
    }
  }
  # nb: the obsolete LOGIN SASL mechanism is also dangerous. Since the
  #     PLAIN mechanism is required to be supported, though, I won't
  #     bother to check for the LOGIN mechanism.

  # If that didn't work, try USER command.
  if (isnull(resp)) {
    c = strcat("USER ", user);
    debug_print("C: '", c, "'.");
    send(socket:soc, data:strcat(c, '\r\n'));
    n = 0;
    while (s = recv_line(socket:soc, length:1024)) {
      if ( ++n > 1024 ) exit(1, "Remote server is sending too much data");
      s = chomp(s);
      debug_print("S: '", s, "'.");
      m = pregmatch(pattern:"^(\+OK|-ERR) ", string:s, icase:TRUE);
      if (!isnull(m)) {
        resp = m[1];
        break;
      }
      resp = "";
    }

    if (resp && resp =~ "OK") {
      c = strcat("PASS ", pass);
      debug_print("C: '", c, "'.");
      send(socket:soc, data:strcat(c, '\r\n'));
      n = 0;
      while (s = recv_line(socket:soc, length:1024)) {
        if ( ++n > 1024 ) exit(1, "Remote server is sending too much data");
        s = chomp(s);
        debug_print("S: '", s, "'.");
        m = pregmatch(pattern:"^(\+OK|-ERR) ", string:s, icase:TRUE);
        if (!isnull(m)) {
          resp = m[1];
          break;
        }
        resp = "";
      }
    }
  }

  # If successful, unencrypted logins are possible.
  if (resp && resp =~ "OK")
  {
    if ( get_kb_item("Settings/PCI_DSS") ) set_kb_item(name:"PCI/ClearTextCreds/" + port,
						value:"The remote POP3 daemon allows credentials to be transmitted in clear text");
    security_report_v4(port:port, severity:SECURITY_NOTE);
  }
}

# Logout.
c = "QUIT";
debug_print("C: '", c, "'.");
send(socket:soc, data:strcat(c, '\r\n'));
n = 0;
while (s = recv_line(socket:soc, length:1024)) {
  if ( ++n > 1024 ) exit(1, "Remote server is sending too much data");
  s = chomp(s);
  debug_print("S: '", s, "'.");
  m = pregmatch(pattern:"^(\+OK|-ERR) ", string:s, icase:TRUE);
  if (!isnull(m)) {
    resp = m[1];
    break;
  }
  resp = "";
}
close(soc);