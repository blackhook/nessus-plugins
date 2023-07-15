#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(65821);
  script_version("1.21");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/02/03");

  script_cve_id("CVE-2013-2566", "CVE-2015-2808");
  script_bugtraq_id(58796, 73684);

  script_name(english:"SSL RC4 Cipher Suites Supported (Bar Mitzvah)");
  script_summary(english:"Reports any supported RC4 based SSL Cipher Suites.");

  script_set_attribute(attribute:"synopsis", value:
"The remote service supports the use of the RC4 cipher.");
  script_set_attribute(attribute:"description", value:
"The remote host supports the use of RC4 in one or more cipher suites.
The RC4 cipher is flawed in its generation of a pseudo-random stream
of bytes so that a wide variety of small biases are introduced into
the stream, decreasing its randomness.

If plaintext is repeatedly encrypted (e.g., HTTP cookies), and an
attacker is able to obtain many (i.e., tens of millions) ciphertexts,
the attacker may be able to derive the plaintext.");
  script_set_attribute(attribute:"see_also", value:"https://www.rc4nomore.com/");
  # https://blog.cryptographyengineering.com/2013/03/12/attack-of-week-rc4-is-kind-of-broken-in/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ac7327a0");
  script_set_attribute(attribute:"see_also", value:"http://cr.yp.to/talks/2013.03.12/slides.pdf");
  script_set_attribute(attribute:"see_also", value:"http://www.isg.rhul.ac.uk/tls/");
  script_set_attribute(attribute:"see_also", value:"https://www.imperva.com/docs/HII_Attacking_SSL_when_using_RC4.pdf");
  script_set_attribute(attribute:"solution", value:
"Reconfigure the affected application, if possible, to avoid use of RC4
ciphers. Consider using TLS 1.2 with AES-GCM suites subject to browser
and web server support.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:ND/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:X/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2013-2566");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"in_the_news", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/03/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/04/05");

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
  exit(1, "A bad protocol was returned from get_tls_dtls_ports(). (" + pp_info["port"] + "/" + pp_info["proto"] + ")");

supported_ciphers = pp_info["ciphers"];
if (isnull(supported_ciphers))
  exit(0, "No ciphers were found for " + pp_info["l4_proto"] + " port " + port + ".");
supported_ciphers = make_list(supported_ciphers);

# Generate the report of supported RC4 ciphers.
c_report = cipher_report(supported_ciphers, name:"_RC4_");
if (isnull(c_report))
  exit(0, "No RC4 cipher suites are supported on " + pp_info["l4_proto"] + " port " + port + ".");

# used by pci_rc4_supported.nasl
if (get_kb_item("Settings/PCI_DSS"));
{
  set_kb_item(name:"PCI/ssl_rc4_supported", value:port);
  replace_kb_item(name:"PCI/ssl_rc4_supported/report/" + port, value:c_report);
}

report =
  '\nList of RC4 cipher suites supported by the remote server :' +
  '\n' + c_report;

security_report_v4(port:port, proto:pp_info["l4_proto"], extra:report, severity:SECURITY_WARNING);
