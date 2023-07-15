#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(26928);
  script_version("1.31");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/02/03");

  script_name(english:"SSL Weak Cipher Suites Supported");
  script_summary(english:"Reports any weak SSL cipher suites that are supported.");

  script_set_attribute(attribute:"synopsis", value:
"The remote service supports the use of weak SSL ciphers.");
  script_set_attribute(attribute:"description", value:
"The remote host supports the use of SSL ciphers that offer weak
encryption.

Note: This is considerably easier to exploit if the attacker is on the
same physical network.");
  # https://www.openssl.org/docs/manmaster/man1/ciphers.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?6527892d");
  script_set_attribute(attribute:"solution", value:
"Reconfigure the affected application, if possible to avoid the use of
weak ciphers.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_set_attribute(attribute:"cvss_score_source", value:"manual");
  script_set_attribute(attribute:"cvss_score_rationale", value:"Score based on an analysis of the vulnerability by Tenable.");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");
  script_cwe_id(
    326, # Inadequate Encryption Strength
    327, # Use of a Broken or Risky Cryptographic Algorithm
    720, # OWASP Top Ten 2007 Category A9 - Insecure Communications
    753, # 2009 Top 25 - Porous Defenses
    803, # 2010 Top 25 - Porous Defenses
    928, # Weaknesses in OWASP Top Ten 2013
    934  # OWASP Top Ten 2013 Category A6 - Sensitive Data Exposure
  );
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/10/08");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"General");

  script_copyright(english:"This script is Copyright (C) 2007-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
  exit(1, "A bad protocol was returned from get_tls_dtls_ports(). (" + pp_info["port"] + "/" + pp_info["proto"] + ")");

supported_ciphers = pp_info["ciphers"];
if (isnull(supported_ciphers))
  exit(0, "No ciphers were found for " + pp_info["l4_proto"] + " port " + port + ".");
supported_ciphers = make_list(supported_ciphers);

# Generate the report of supported weak ciphers.
report = cipher_report(supported_ciphers, eq:CIPHER_STRENGTH_LOW);
if (isnull(report))
  exit(0, "No weak SSL ciphers are supported on " + pp_info["l4_proto"] + " port " + port + ".");

report =
  '\nHere is the list of weak SSL ciphers supported by the remote server :' +
  '\n' + report;

security_report_v4(port:port, proto:pp_info["l4_proto"], extra:report, severity:SECURITY_WARNING);

