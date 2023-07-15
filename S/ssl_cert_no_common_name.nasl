#TRUSTED 14c5f51cbd1f1986af5c52854968ec1af411fdd02d9bdd806d4f1588900365db0dfe809e748ac5c68411ec24dc8849d87b45da77ec55defdc00a501995f2201efa9d1023c4d30b9f2aa9db0155e3b072b28c42f7088fa7fdd73cc1f5d644c6f99831d004551861becf6d93e27d84c023a03631cf69039cc764f2a0aff963d09f02f4d931adf28274b2fc32a21ac136f89a8a2fc234cf2314d5f5766c337eea3a94463827dc2454de1e0d1adaceb5ca6e7b7b5eec7483e66e43355b8744b7d7c8dc1ae64d8c26ca0b90740ad76e3d07afb30197ad0f0e742dec215f0dc8e7af663c8ab6874f974831a1270ecce003534ce46c482a3d4ed27d2a1f67bab7c945fc3a06b44c379e119babdb118c46147246e5729166b360e97d6956e58fd3655647c6f782a08021ae35a75376191399a2582a00cc5f87c7378e3f952a3cb1489eb6191b3b87953d41714f235b565261ca29874e59bb2ba6920af6ea6bef795e30b1726ac717a5dbc90c50b293d17c6b92292929bdccda130216d0239177812c2411d0cd0641def26c6ed69fa99cf119e555a328cb69569830cbc861a1fcd45730b49da83b91cf20b36a00c05d5a024cd434d715b3935d83e68fb29905fef2fa5c8179998152799b2a94db76d03bbc6a8e411668828c8c2526607b3a82362d6a97d5aa703f4687fcfc61bafba374282aa3c68974b4ec8b91f2462f959fb21d3a3828
#TRUST-RSA-SHA256 648d730f632840cf934e990d4d63cc900d93a7ae40bdf6be31857f46803bdef0416bad28992e8678f4bbf535086e43842aa9f12c6d6fa7453736da69b481cdef9f9d14c6aaa4e8cb995f51412ec96c565c3d9f2505742b4ee96d8f3bf63e2c095353a1ff2c425901c7151d18a213662fefa0fa613eb823bca7aa0cbf76652430ad4b4ab404dba68d0af7dee13ebc9d7a09c11e771ba3d3bc5bc3cc500a1e2b4a74fffc6d572a5b355e706c77d316bc5e296758fdb62897af039781b3336353e0507e841510b8378fdb43e8277cadd8e777a4795caeedda278d9cc1e661a24439314548d40b97957b2af63973cb6bfc83c052cdfe1d189e0536765f8dbb8d55f627e71dd030bf180b145325e7f5e584d8c00176b88e782129356abff38f2bbc35d76354c9c8deb6bf91ff9c2360ba3e2d0c824dd907c4782d8d11b3cf5dcf38141f7cf6f6c5aa609f38cf43c8bc09edb5e0c910511dd245b3549f886cf4da451881284c3538e5b48ec3c8cd2de97aa54a250381ed840dd7b0f3f97f24cd3fc775e721947960112eb51f76b4b2ecb9b15fff5de7e8c3870e8586087a58a392f99fa35e6d72029622a10358c6a372bd49fd7eb6083cee373a99690f8bbf693c3a08d93a880f0686aa3b939d3633331b7e0663f6a49e4e4aa773a64a631807f1c8f295a8f7ccca519e309afd31109402993ab5cb2fd3f5bd20e057affa99664be987

#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include("compat.inc");

if (description)
{
  script_id(159544);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/11/30");
 
  script_name(english:"SSL Certificate with no Common Name");
 
  script_set_attribute(attribute:"synopsis", value:
"Checks for an SSL certificate with no Common Name");
  script_set_attribute(attribute:"description", value:
"The remote system is providing an SSL/TLS certificate without a subject common name field. While this is not required
in all cases, it is recommended to ensure broad compatibility.");
  script_set_attribute(attribute:"see_also", value:"https://datatracker.ietf.org/doc/html/rfc5280#section-4.1.2.6");
  script_set_attribute(attribute:"risk_factor", value:"None");
  script_set_attribute(attribute:"solution", value:"n/a");

  script_set_attribute(attribute:"plugin_publication_date", value:"2022/04/06");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO); 
  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"General");

  script_dependencies("ssl_supported_versions.nasl", "find_service_dtls.nasl");
  script_require_ports("SSL/Supported", "DTLS/Supported");
  exit(0);
}

include('x509_func.inc');

if (!get_kb_item('SSL/Supported') && !get_kb_item('DTLS/Supported'))
  exit(1, 'Neither the "SSL/Supported" nor the "DTLS/Supported" flag is set.');

var pp_info = get_tls_dtls_ports(fork:TRUE, dtls:TRUE, check_port:TRUE);
var port = pp_info['port'];
if (isnull(port))
  exit(1, 'The host does not appear to have any TLS or DTLS based services.');

var cert;
if (pp_info['proto'] == 'tls')
  cert = get_server_cert(port:port, encoding:'der', dtls:FALSE);
else if(pp_info['proto'] == 'dtls')
  cert = get_server_cert(port:port, encoding:'der', dtls:TRUE);
else
  exit(1, 'A bad protocol was returned from get_tls_dtls_ports(). (' + pp_info['port'] + '/' + pp_info['proto'] + ')');

if (isnull(cert))
  exit(1, 'Failed to read the certificate for the service listening on ' + pp_info['l4_proto'] + ' port ' + port + '.');

var parsed_cert = parse_der_cert(cert:cert);
if (isnull(parsed_cert))
  exit(1, 'Failed to parse the certificate from the service listening on ' + pp_info['l4_proto'] + ' port ' + port + '.');

var subject_rdns = add_rdn_seq(seq:parsed_cert.tbsCertificate.subject);
foreach var rdn (split(subject_rdns, sep:'\n', keep:FALSE))
{
  if (rdn =~ "^Common Name: ")
  {
    var cn = rdn - 'Common Name: ';
    if (!empty_or_null(cn))
      audit(AUDIT_NOT_DETECT, 'A certificate with no common name', port);
  }
}

var report = dump_certificate(cert:parsed_cert);
if (!report)
  exit(1, 'Failed to dump the certificate from the service listening on ' + pp_info['l4_proto'] + ' port ' + port + '.');

report += '\nPEM certificate : \n\n' + '-----BEGIN CERTIFICATE-----\n' + base64(str:cert) + '\n-----END CERTIFICATE-----';

security_report_v4(port:port, proto:pp_info['l4_proto'], extra:report, severity:SECURITY_NOTE);
