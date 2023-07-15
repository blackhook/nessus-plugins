#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(70544);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/02/03");

  script_name(english:"SSL Cipher Block Chaining Cipher Suites Supported");
  script_summary(english:"Reports any SSL CBC cipher suites that are supported.");

  script_set_attribute(attribute:"synopsis", value:
"The remote service supports the use of SSL Cipher Block Chaining
ciphers, which combine previous blocks with subsequent ones.");
  script_set_attribute(attribute:"description", value:
"The remote host supports the use of SSL ciphers that operate in Cipher
Block Chaining (CBC) mode.  These cipher suites offer additional
security over Electronic Codebook (ECB) mode, but have the potential to
leak information if used improperly.");
  script_set_attribute(attribute:"see_also", value:"https://www.openssl.org/docs/manmaster/man1/ciphers.html");
  # https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Cipher-block_chaining_.28CBC.29
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?cc4a822a");
  script_set_attribute(attribute:"see_also", value:"https://www.openssl.org/~bodo/tls-cbc.txt");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2013/10/22");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"General");

  script_copyright(english:"This script is Copyright (C) 2013-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssl_supported_ciphers.nasl");
  script_require_ports("SSL/Supported", "DTLS/Supported");

  exit(0);
}

include("audit.inc");
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
  exit(1, "A bad protocol was returned from get_tls_dtls_ports(). (" + port + "/" + pp_info["proto"] + ")");

supported_ciphers = pp_info["ciphers"];
if(isnull(supported_ciphers))
  exit(1, "No TLS ciphers detected for port " + port + ".");
supported_ciphers = make_list(supported_ciphers);

# Generate the report of supported CBC ciphers.
report = cipher_report(supported_ciphers, name:"_CBC_");
if (isnull(report))
  exit(0, "No TLS CBC ciphers are supported on " + pp_info["l4_proto"] + " port " + port + ".");

report =
  '\nHere is the list of SSL CBC ciphers supported by the remote server :' +
  '\n' + report;

security_report_v4(port:port, proto:pp_info["l4_proto"], extra:report, severity:SECURITY_NOTE);

