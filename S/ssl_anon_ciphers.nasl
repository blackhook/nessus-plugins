#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(31705);
  script_version("1.30");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/02/03");

  script_cve_id("CVE-2007-1858");
  script_bugtraq_id(28482);

  script_name(english:"SSL Anonymous Cipher Suites Supported");
  script_summary(english:"Reports anonymous SSL ciphers suites that are supported");
 
  script_set_attribute(attribute:"synopsis", value:
"The remote service supports the use of anonymous SSL ciphers.");
  script_set_attribute(attribute:"description", value:
"The remote host supports the use of anonymous SSL ciphers. While this
enables an administrator to set up a service that encrypts traffic
without having to generate and configure SSL certificates, it offers
no way to verify the remote host's identity and renders the service
vulnerable to a man-in-the-middle attack.

Note: This is considerably easier to exploit if the attacker is on the
same physical network." );
  # https://wiki.openssl.org/index.php/Manual:Ciphers(1)
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?3a040ada");
  script_set_attribute(attribute:"solution", value:
"Reconfigure the affected application if possible to avoid use of weak
ciphers." );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2007-1858");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_publication_date", value: "2008/03/28");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"vuln_publication_date", value:"2007/05/09");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Service detection");

  script_copyright(english:"This script is Copyright (C) 2008-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if(isnull(supported_ciphers))
  exit(1, "No TLS ciphers detected for port " + port + ".");
supported_ciphers = make_list(supported_ciphers);

# Generate the report of supported anonymous ciphers.
report = cipher_report(supported_ciphers, field:"auth", desc:"None");
if (isnull(report))
  exit(0, "No SSL anonymous ciphers are supported on " + pp_info["l4_proto"] + " port " + port + ".");

# used by pci_anon_key_exchanges.nasl
if (get_kb_item("Settings/PCI_DSS"))
{
  set_kb_item(name:"PCI/anon_keyex_ssl", value:port);
  replace_kb_item(name:"PCI/anon_keyex_ssl/report/" + port, value:report);
}

report =
  '\nThe following is a list of SSL anonymous ciphers supported by the remote ' + pp_info["l4_proto"] + ' server :' +
  '\n' + report;

security_report_v4(port:port, proto:pp_info["l4_proto"], extra:report, severity:SECURITY_NOTE);

