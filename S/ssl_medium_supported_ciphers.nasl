#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(42873);

  script_cve_id("CVE-2016-2183");
  script_version("1.21");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/02/03");

  script_name(english:"SSL Medium Strength Cipher Suites Supported (SWEET32)");
  script_summary(english:"Reports supported medium strength SSL cipher suites.");
 
  script_set_attribute(attribute:"synopsis", value:
"The remote service supports the use of medium strength SSL ciphers.");
  script_set_attribute(attribute:"description", value:
"The remote host supports the use of SSL ciphers that offer medium
strength encryption. Nessus regards medium strength as any encryption
that uses key lengths at least 64 bits and less than 112 bits, or 
else that uses the 3DES encryption suite.

Note that it is considerably easier to circumvent medium strength
encryption if the attacker is on the same physical network.");
  script_set_attribute(attribute:"see_also", value:"https://www.openssl.org/blog/blog/2016/08/24/sweet32/");
  script_set_attribute(attribute:"see_also", value:"https://sweet32.info");
  script_set_attribute(attribute:"solution", value:
"Reconfigure the affected application if possible to avoid use of
medium strength ciphers.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2016-2183");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/08/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/11/23");

  script_set_attribute(attribute:"plugin_type", value:"remote");
   script_set_attribute(attribute:"in_the_news", value:"true");
  script_end_attributes();
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"General");
 
  script_copyright(english:"This script is Copyright (C) 2009-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (!max_index(supported_ciphers))
  exit(0, "No ciphers were found for " + pp_info["l4_proto"] + " port " + port + ".");

# Generate the report of supported medium strength ciphers.
report = cipher_report(supported_ciphers, eq:CIPHER_STRENGTH_MEDIUM);
if (isnull(report))
  exit(0, "No medium strength SSL ciphers are supported on " + pp_info["l4_proto"] + " port " + port + ".");

security_report_v4(port:port, proto:pp_info["l4_proto"], extra:report, severity:SECURITY_WARNING);

