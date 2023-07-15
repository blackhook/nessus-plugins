#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(66848);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/02/03");

  script_name(english:"SSL Null Cipher Suites Supported");
  script_summary(english:"Reports any null SSL cipher suites that are supported.");

  script_set_attribute(attribute:"synopsis", value:
"The remote service supports the use of null SSL ciphers.");
  script_set_attribute(attribute:"description", value:
"The remote host supports the use of SSL ciphers that offer no
encryption at all.

Note: This is considerably easier to exploit if the attacker is on the
same physical network.");
  # https://wiki.openssl.org/index.php/Manual:Ciphers(1)
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?3a040ada");
  script_set_attribute(attribute:"solution", value:
"Reconfigure the affected application, if possible to avoid the use of
null ciphers.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_set_attribute(attribute:"cvss_score_source", value:"manual");
  script_set_attribute(attribute:"cvss_score_rationale", value:"Score based on an analysis of the vulnerability by Tenable.");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");

  script_set_attribute(attribute:"plugin_publication_date", value:"2013/06/10");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"General");

  script_copyright(english:"This script is Copyright (C) 2013-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_dependencies("ssl_supported_versions.nasl", "find_service_dtls.nasl");
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
if (!max_index(supported_ciphers))
  exit(0, "No ciphers were found for " + pp_info["l4_proto"] + " port " + port + ".");

# Generate the report of supported null ciphers.
report = cipher_report(supported_ciphers, eq:CIPHER_STRENGTH_NULL);
if (isnull(report))
  exit(0, "No null SSL ciphers are supported on " + pp_info["l4_proto"]+ " port " + port + ".");

report =
  '\nHere is the list of null SSL ciphers supported by the remote server :' +
  '\n' + report;

security_report_v4(port:port, proto:pp_info["l4_proto"], extra:report, severity:SECURITY_WARNING);

