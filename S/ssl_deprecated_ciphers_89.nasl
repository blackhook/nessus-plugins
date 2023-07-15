#
# (C) Tenable Network Security, Inc.
#
include('compat.inc');

if (!defined_func("nasl_level") || nasl_level() < 80900 ) exit(0, "Nessus is older than 8.9");

if (description)
{
  script_id(132675);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/02/03");

  script_xref(name:"IAVA", value:"0001-A-0635");

  script_name(english:"SSL/TLS Deprecated Ciphers Unsupported");
  script_summary(english:"Checks if the remote host advertises deprecated SSL/TLS cipher suites.");

  script_set_attribute(attribute:"synopsis", value:"The remote host uses deprecated SSL/TLS ciphers which are unsupported");
  script_set_attribute(attribute:"description", value:"The remote host has open SSL/TLS ports which advertise 
deprecated cipher suites. The ciphers contained in these suites are no longer supported by most major ssl libraries
such as OpenSSL, NSS, Mbed TLS, and wolfSSL and, as such, should not be used for secure communication.

Nessus 8.9 and later no longer supports these ciphers.");
  script_set_attribute(attribute:"solution", value:"Upgrade to a cipher suite which does not contain deprecated ciphers.");
  script_set_attribute(attribute:"risk_factor", value:"Critical");

  script_set_attribute(attribute:"plugin_publication_date", value:"2020/01/06");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"General");

  script_copyright(english:"This script is Copyright (C) 2020-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssl_supported_ciphers.nasl");
  script_exclude_keys("global_settings/disable_test_ssl_based_services");
  exit(0);
}

include('audit.inc');
include('byte_func.inc');
include('lists.inc');
include('ssl_funcs.inc');

if (get_kb_item('global_settings/disable_test_ssl_based_services'))
  exit(1, 'Not testing SSL based services per user config.');

deprecated_ciphers = [
  'TLS1_CK_RSA_EXPORT_WITH_RC4_40_MD5',
  'TLS1_CK_RSA_EXPORT_WITH_RC2_CBC_40_MD5',
  'TLS1_CK_RSA_EXPORT_WITH_DES40_CBC_SHA',
  'TLS1_CK_RSA_WITH_DES_CBC_SHA',
  'TLS1_CK_DH_DSS_WITH_DES_CBC_SHA',
  'TLS1_CK_DH_DSS_WITH_3DES_EDE_CBC_SHA',
  'TLS1_CK_DH_RSA_WITH_DES_CBC_SHA',
  'TLS1_CK_DH_RSA_WITH_3DES_EDE_CBC_SHA',
  'TLS1_CK_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA',
  'TLS1_CK_DHE_DSS_WITH_DES_CBC_SHA',
  'TLS1_CK_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA',
  'TLS1_CK_DHE_RSA_WITH_DES_CBC_SHA',
  'TLS1_CK_DH_anon_EXPORT_WITH_RC4_40_MD5',
  'TLS1_CK_DH_anon_EXPORT_WITH_DES40_CBC_SHA',
  'TLS1_CK_DH_anon_WITH_DES_CBC_SHA',
  'TLS1_CK_DH_DSS_WITH_AES_128_CBC_SHA',
  'TLS1_CK_DH_RSA_WITH_AES_128_CBC_SHA',
  'TLS1_CK_DH_DSS_WITH_AES_256_CBC_SHA',
  'TLS1_CK_DH_RSA_WITH_AES_256_CBC_SHA',
  'TLS1_DH_DSS_WITH_AES_128_CBC_SHA256',
  'TLS1_DH_RSA_WITH_AES_128_CBC_SHA256',
  'TLS1_CK_DH_DSS_WITH_CAMELLIA_128_CBC_SHA',
  'TLS1_CK_DH_RSA_WITH_CAMELLIA_128_CBC_SHA',
  'TLS1_DH_DSS_WITH_AES_256_CBC_SHA256',
  'TLS1_DH_RSA_WITH_AES_256_CBC_SHA256',
  'TLS1_CK_DH_DSS_WITH_CAMELLIA_256_CBC_SHA',
  'TLS1_CK_DH_RSA_WITH_CAMELLIA_256_CBC_SHA',
  'TLS1_CK_DH_DSS_WITH_SEED_CBC_SHA',
  'TLS1_CK_DH_RSA_WITH_SEED_CBC_SHA',
  'TLS12_DH_RSA_WITH_AES_128_GCM_SHA256',
  'TLS12_DH_RSA_WITH_AES_256_GCM_SHA384',
  'TLS12_DH_DSS_WITH_AES_128_GCM_SHA256',
  'TLS12_DH_DSS_WITH_AES_256_GCM_SHA384',
  'TLS1_CK_ECDH_ECDSA_WITH_RC4_128_SHA',
  'TLS1_CK_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA',
  'TLS1_CK_ECDH_ECDSA_WITH_AES_128_CBC_SHA',
  'TLS1_CK_ECDH_ECDSA_WITH_AES_256_CBC_SHA',
  'TLS1_CK_ECDH_RSA_WITH_RC4_128_SHA',
  'TLS1_CK_ECDH_RSA_WITH_3DES_EDE_CBC_SHA',
  'TLS1_CK_ECDH_RSA_WITH_AES_128_CBC_SHA',
  'TLS1_CK_ECDH_RSA_WITH_AES_256_CBC_SHA',
  'TLS1_ECDH_ECDSA_WITH_AES_128_CBC_SHA256',
  'TLS1_ECDH_ECDSA_WITH_AES_256_CBC_SHA384',
  'TLS1_ECDH_RSA_WITH_AES_128_CBC_SHA256',
  'TLS1_ECDH_RSA_WITH_AES_256_CBC_SHA384',
  'TLS12_ECDH_ECDSA_WITH_AES_128_GCM_SHA256',
  'TLS12_ECDH_ECDSA_WITH_AES_256_GCM_SHA384',
  'TLS12_ECDH_RSA_WITH_AES_128_GCM_SHA256',
  'TLS12_ECDH_RSA_WITH_AES_256_GCM_SHA384'
];

report_header =
'The remote host has listening SSL/TLS ports which only advertise deprecated cipher suites which are no longer\n' +
'supported in Nessus 8.9 and later. The deprecated ciphers are outlined below:\n\n';

##
# Determine if all given ciphers are present in the deprecated_ciphers list.
#
# @param <ciphers:list> List of ciphers advertised.
# @return TRUE if all ciphers are present, FALSE otherwise.
##
function all_ciphers_in_deprecated_list(ciphers)
{
  if (empty_or_null(ciphers))
    return FALSE;
  local_var cipher;
  foreach cipher(ciphers)
  {
    if (!collib::contains(deprecated_ciphers, cipher)){
      return FALSE;
    }
  }
  return TRUE;
}

##########
## Main ##
##########
ports_and_deprecated_ciphers = {};

foreach pp_info(get_tls_dtls_ports(dtls:TRUE, ciphers:TRUE))
{
  port = pp_info["port"];
  kbs = pp_info["ciphers"];

  if(pp_info["proto"] != "tls" && pp_info["proto"] != "dtls")
    continue;

  if (empty_or_null(kbs))
    continue;

  cipher_list = make_list(kbs);
  if(all_ciphers_in_deprecated_list(ciphers:cipher_list))
    ports_and_deprecated_ciphers[port] = cipher_list;
}

if (empty_or_null(keys(ports_and_deprecated_ciphers)))
  audit(AUDIT_HOST_NOT, 'affected');

foreach port (sort(keys(ports_and_deprecated_ciphers)))
{
  report = report_header;
  report += cipher_report(ports_and_deprecated_ciphers[port]);
  security_report_v4(port:port, extra:report, severity:SECURITY_HOLE);
}
