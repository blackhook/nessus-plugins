#TRUSTED 39ea5ed43122c83c648c0c2c6284ae7aeaecd6383ca3e8e598941a9d18dade3608e4a94815bcd9b8b5acb43000ed6b9045e863dd9df23713c112edce04e4317ff656dfe88b0ef7ff2a7ea5dedfc69e963e23f1267a63280ba383c89e530ad00ce60593b95399fe9a76706ff96a497ac8e740e40649ec05b0d861c3e3ee07c0529c1f635bb0b998ad58747c5dc3521873eefc9d8328bb26a464e54a4389a6903e86d8952ef726ee6bf52234840aa763237c3c9eff53c9de286de9b8e2e24c0dc266cc7bda6a7089554636b5bd8e30050a52d34709d7e9099cda1deceffb014d2e2f81e9ead87007ed98ec78de7c2e148ba6c4d08ed9fdd466757c2c9c01f8dd7b45be338c0e598a89e61b078f79c7414bbb10ec4f2ed3b807e7b9f1f5a640b6ba0b70476f1232ea6c18014163417e27c8706e30e1b559d286059d906ff8fa035c600636449168777d157a281c70599581f873b90d5fd72030cea0720af2a8dc01b517e81587562496be3af1d2a04e68e4eaf5605f81c7258eb40702139952fc462a75e42bf399a23a09d9ab3edc9c36b73ba4e6cb0a8aeb1c4e0f1415cc86a461a0c74fe4bff1ebba47f903a7161040a7e8f0f0f6ed60a529171f48724dd1fc409016c2b46a05b148b604d7139910261253ae935d8c959f67bdccf2a29034112cd9bb195a51d40ffcdcfafcd3580257bbe42c9d17133de11d31aa68ee338a6036
#
# (C) Tenable Network Security, Inc.
#
# Starting with Nessus 3.2.1, this script replaces 
# ssl_ciphers.nes
#

# Check if this version of nessusd is too old
if ( NASL_LEVEL < 3208 ) exit(0);


include("compat.inc");

if (description)
{
 script_id(10863);
 script_version("1.22");
 script_set_attribute(attribute:"plugin_modification_date", value:"2021/02/03");
 
 script_name(english:"SSL Certificate Information");
 script_summary(english:"Displays the server SSL/TLS certificate");
 
 script_set_attribute(attribute:"synopsis", value:
"This plugin displays the SSL certificate.");
 script_set_attribute(attribute:"description", value:
"This plugin connects to every SSL-related port and attempts to 
extract and dump the X.509 certificate.");
 script_set_attribute(attribute:"risk_factor", value:"None");
 script_set_attribute(attribute:"solution", value:"n/a");

 script_set_attribute(attribute:"plugin_publication_date", value:"2008/05/19");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_GATHER_INFO); 
 script_copyright(english:"This script is Copyright (C) 2004-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
 script_family(english:"General");

 script_dependencies("ssl_supported_versions.nasl", "find_service_dtls.nasl");
 script_require_ports("SSL/Supported", "DTLS/Supported");
 exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("x509_func.inc");

if(!get_kb_item("SSL/Supported") && !get_kb_item("DTLS/Supported"))
  exit(1, "Neither the 'SSL/Supported' nor the 'DTLS/Supported' flag is set.");

pp_info = get_tls_dtls_ports(fork:TRUE, dtls:TRUE, check_port:TRUE);
port = pp_info["port"];
if (isnull(port))
  exit(1, "The host does not appear to have any TLS or DTLS based services.");

if(pp_info["proto"] == 'tls')
  cert = get_server_cert(port:port, encoding:"der", dtls:FALSE);
else if(pp_info["proto"] == 'dtls')
  cert = get_server_cert(port:port, encoding:"der", dtls:TRUE);
else
  exit(1, "A bad protocol was returned from get_tls_dtls_ports(). (" + pp_info["port"] + "/" + pp_info["proto"] + ")");

if (isnull(cert))
  exit(1, "Failed to read the certificate for the service listening on " + pp_info["l4_proto"] + " port " + port + ".");

# calculate fingerprints on raw certificate
fingerprints = 'Fingerprints : \n\n' +
add_hex_string(name:"SHA-256 Fingerprint", data:SHA256(cert)) + 
add_hex_string(name:"SHA-1 Fingerprint", data:SHA1(cert)) + 
add_hex_string(name:"MD5 Fingerprint", data:MD5(cert)) + '\n';

parsed_cert = parse_der_cert(cert:cert);
if (isnull(parsed_cert)) exit(1, "Failed to parse the certificate from the service listening on " + pp_info["l4_proto"] + " port " + port + ".");

report = dump_certificate(cert:parsed_cert);
if (!report) exit(1, "Failed to dump the certificate from the service listening on " + pp_info["l4_proto"] + " port " + port + ".");

report += fingerprints;

report += '\nPEM certificate : \n\n' + '-----BEGIN CERTIFICATE-----\n' + base64(str:cert) + '\n-----END CERTIFICATE-----';

security_report_v4(port:port, proto:pp_info["l4_proto"], extra:report, severity:SECURITY_NOTE);

