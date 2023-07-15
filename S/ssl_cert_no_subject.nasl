#TRUSTED 959c7de2341edb0188c6d4087673f7e31e93f6a35be62d759f5df74943a1bce6543c7ca480c80330780d58aed4a9a31999f54b7e0cbecd8c10253d02c1a8a83febf8c7bf18c78ad29bd823ca91b7bf735f9305310fff68d0de900201c9d04eeac3a4e23d9b4cb4532f316c6acdfb376a1b00e235f0a9cd7d0fd07a43fedfb19f3fbb0bed12edc03a1dedb6707f154c2c36ab35fa58718711b6858d3ae25aa4f3b18bf32594f96d4fa2a99ba1c2e484ce9255ad7f2bf84e1dad0b155679d42a570f7df26267ffb63dd439fa6765effa92aae4c33a391e1f05fe115bdd4350c211b70ea5e91af8a3126f7a6fffdd844769926dabcf31a46c86a666464e0c7c0ae90f987fed1f950dfaf1fe0f351fd59a37e51d99c8c6d803e50868072179ddfb725fceffc76d0b0f801293e423e67d93d60569f41af4e171c68b42e4a28317a6375639a879d3e001330e9d15683c33fb644300e53464caffb683e9d735e91d901335821c07fc7a606357554fbc6880262b5c7f920adea8a844b4a174b07b7257e7c6cc748738fcc1b89c085e578617026e29d08e820f57d33bfd811a38b62f3410d318395ae008c99e0e70b3f3ffae6f60a714b50de527c4b555687e5ac442ac56837ddc37222b0c6ed35e3e317fb305360095c00f1bffd146e68c9f94a310984381e506520b505612381a441f0cdccfd327b4a15c64b7c1f2e384519008466477
#TRUST-RSA-SHA256 6bea676e3ce24979c2a3ebcde09dbfce29bf9ff5c22e65b94f4cf53a39e31ebcb9f8c88448110e8fe80601d9df334a3eb4843989ec3a408a1dab1ddfbd7078969f3d3792c2859903a728cc5b54b2ccae722e6015cab7793285cb9f2a91f69a1e5df686e6179a78a3b40156328e4cc2f696e5e4dd7bc6583b327329e03bb527bffd3112dbea97244c1606a3d7319d3be4ebe618537dfea2aae8f366a1d83b738f9d7a1faccd01d21d9a0f220315b28c50a2deb95cd1e1d7bb0340a03ace05499c8be6f18726a26554a00282b5e904d2aa29424be3a1b4757f745e736dabeabfa245d6d049dff39502875c222940ee8ad8ae8fc9389a14bcb99b34379fd7beb1a239432f358e8afc1e14f1e9a4ffe2b68fadcec14077d2e525315ed12024e45c098f1bbc0bd0437e642fdcc8a50d28c55e5b2e107f02a3e59d051946eb55ec68f2eb2060517851d7f799826cec9981d8c9ee0a086b31529b8ac1fe94af6ce21923509df8f311093900315dba04cc1ec6b9197fab0e6f5ac5f16964e1236b0925a0be01ed944e13707417cb38b57bf60d9358e628c3d45cd3332338e2d054a980c836e887d21ac5bca113578acbb7f3bbe8982677a1dccb9a2a93072958abac08e46064391ca856cb2dfab60e7ce24b1d0d1dabe913207a19de39e912c2cbd3ceb342b28888153a99b266349f2eaeab02b93dd67b067427d0401e1a0573d0e10cdb

#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include("compat.inc");

if (description)
{
  script_id(159545);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/11/30");
 
  script_name(english:"SSL Certificate with no Subject");
 
  script_set_attribute(attribute:"synopsis", value:
"Checks for an SSL certificate with no Subject");
  script_set_attribute(attribute:"description", value:
"The remote system is providing an SSL/TLS certificate without a subject field. While this is not required in all cases,
it is recommended to ensure broad compatibility.");
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

if (!empty_or_null(parsed_cert.tbsCertificate.subject))
{
  audit(AUDIT_NOT_DETECT, 'A certificate with no subject', port);
}

var report = dump_certificate(cert:parsed_cert);
if (!report)
  exit(1, 'Failed to dump the certificate from the service listening on ' + pp_info['l4_proto'] + ' port ' + port + '.');

report += '\nPEM certificate : \n\n' + '-----BEGIN CERTIFICATE-----\n' + base64(str:cert) + '\n-----END CERTIFICATE-----';

security_report_v4(port:port, proto:pp_info['l4_proto'], extra:report, severity:SECURITY_NOTE);
