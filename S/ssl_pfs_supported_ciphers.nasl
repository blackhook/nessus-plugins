#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(57041);
  script_version("1.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/03/09");

  script_name(english:"SSL Perfect Forward Secrecy Cipher Suites Supported");
  script_summary(english:"Reports any SSL PFS cipher suites that are supported.");

  script_set_attribute(attribute:"synopsis", value:
"The remote service supports the use of SSL Perfect Forward Secrecy
ciphers, which maintain confidentiality even if the key is stolen.");
  script_set_attribute(attribute:"description", value:
"The remote host supports the use of SSL ciphers that offer Perfect
Forward Secrecy (PFS) encryption.  These cipher suites ensure that
recorded SSL traffic cannot be broken at a future date if the server's
private key is compromised.");

  script_set_attribute(attribute:"see_also", value:"https://www.openssl.org/docs/manmaster/man1/ciphers.html");
  script_set_attribute(attribute:"see_also", value:"https://en.wikipedia.org/wiki/Diffie-Hellman_key_exchange");
  script_set_attribute(attribute:"see_also", value:"https://en.wikipedia.org/wiki/Perfect_forward_secrecy");

  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2011/12/07");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"General");

  script_copyright(english:"This script is Copyright (C) 2011-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssl_supported_ciphers.nasl");
  script_require_ports("SSL/Supported", "DTLS/Supported");

  exit(0);
}

include("byte_func.inc");
include("global_settings.inc");
include("misc_func.inc");
include("ssl_funcs.inc");


if(!get_kb_item("SSL/Supported") && !get_kb_item("DTLS/Supported"))
  exit(1, "Neither the 'SSL/Supported' nor the 'DTLS/Supported' flag is set.");

pp_info = get_tls_dtls_ports(fork:TRUE, dtls:TRUE, check_port:TRUE, ciphers:TRUE);
port = pp_info["port"];
if (isnull(port))
  exit(1, "The host does not appear to have any TLS or DTLS based services.");

if(pp_info["proto"] != "tls" && pp_info["proto"] != "dtls")
  exit(1, "A bad protocol was returned from get_tls_dtls_ports(). (" + pp_info["port"] + "/" + pp_info["proto"] + ")");

supported_ciphers = pp_info["ciphers"];
if (isnull(supported_ciphers))
  exit(0, "No ciphers were found for " + pp_info["l4_proto"] + " port " + port + ".");
supported_ciphers = make_list(supported_ciphers);

# Generate the report of supported PFS ciphers.
report = cipher_report(supported_ciphers, name:"_(EC)?(DHE|EDH)_");
if (isnull(report))
  exit(0, "No SSL PFS ciphers are supported on " + pp_info["l4_proto"] + " port " + port + ".");

report =
  '\nHere is the list of SSL PFS ciphers supported by the remote server :' +
  '\n' + report;

security_note(port:port, proto:tolower(pp_info["l4_proto"]), extra:report);

