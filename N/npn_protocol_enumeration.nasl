#TRUSTED 119df8f40ff837445606030e80593784d1444bc47e919bf6280c52166e134d6b0ae945cc9dff1281d66b009d6d258857fc2a4556987228d62e61580bb7a3ccb2c3cd7dd16e77a4f3326321d89bc754700919b9c243ce5fe12bbab7802745e6fa0b172512e5c64de2b161448b07958f615c2aa4e21cb85e78c5688c72ebd51e6e65f7e256a18f177b85fd3660f07a65c85547f00acc846bb905a259a4bed59a9fa04884f3e1db29851be1c54892c04da59c1f4a923b7f2f926a0946863d612cab1f78fce0f7d0e7a814bd3f9d3c9a59df0271561c414837b67e2d8f3dfcb0f6b93f808631ed93c785ae8a861c18013f2ff7d0541fcd7d8dcbfddd2d65c9c49dd81525f188a275c7339d25fb5635f8fad540265d5b2eeee88b19a9b02b438b9ae3cc7c733d03b9938e2e3d453d023006b0f506c8cfb826cc4e07e359e129b61abca742198aa35010ccd41a9eece65e2069de314aded378e255ac04b30b51a9cea1ada6c9eee5024c0f01304fcc276887c27cbe9303002e6a53beb5f6f0cf764bdf71286f7c4c0ac8868ddb4cd700bb8ca32780586c0e5835ebc50b56fa8d86828fac1f917d073ffc4f7e08d0fa3d6d57bbffc0affd1926c8aba547c07274a5561bc6c7e90416b9a1569bc9b4b6f504cebbe05f86d08ac59e528df775c6fc94df29ea79b429ebcdf1d1fc2f2e072926910d736525af9ce318d70687d8a8901a10b7
#TRUST-RSA-SHA256 6a14709e30c4115c6df68b6d1db8db3c69f3bf126919491281666b3e7bcd7d0de665efe07169a0a26bc55d84b6132e6e45309c765bc36ff570325c06d1e72b4cd5605efdb9db98f67609547b5f465c2a7cf5ff923a0c0c2cf73efcc6c38f4b60fb30b0f5ef108bf606409c9fc3239cae36d3bab6aeaf6e63371860f7688586371fecaa9e16622fe049ddcd1364e8bfd48f92b694d0a3857b1571db9ecb5782e4cc454284420740329b5440c1a696021b97fafc8748dc6279075c7077bac08cfa49e54530ab158af1714cedcd146869522b7f5aa3b4e2a915c8e4904be78b884a2197dbd3349a9e4bebb28f3d0ed41e73d7f1ffc291cd743359f0cdfc00ca046b9a5801335c1c3e708e9bcdd6bf6cdddda7faaa12666035511bc71a9e1442cf934510e981b680002d6b51fed0768c6fec2a9873b2d424466b417c296768e009e62f7dd44bf16b821dddd1e98a09224efa9b1ab93b3e7a5893698025785e16eac509cf96cdc6fc03267c57165ad6d1649a7825573b55c0cfca80a03df0e662357f57e1783a7d67ae9ef8652fd5e2114213ba032394f3be69f27cf70fc18cfd5b2f712321fa5b5f5505a69255a3c0304bb0a8e55991a776f91287a821c920d088673a177250d6ddb3576bd858a81c42bd37f0ad0efba41e0f481193896e77ee217ec4bddf353de4e81221583ebaf449a53191ab93cac9ec0154e6bbf4a55289d011
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(87242);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/07/10");

  script_name(english:"TLS NPN Supported Protocol Enumeration");
  script_summary(english:"Enumerates TLS NPN supported protocols.");

  script_set_attribute(attribute:"synopsis",value:
"The remote host supports the TLS NPN extension.");
  script_set_attribute(attribute:"description",value:
"The remote host supports the TLS NPN (Transport Layer Security Next
Protocol Negotiation) extension. This plugin enumerates the protocols
the extension supports.");
  script_set_attribute(attribute:"see_also",value:"https://tools.ietf.org/id/draft-agl-tls-nextprotoneg-03.html");
  script_set_attribute(attribute:"solution",value:"n/a");
  script_set_attribute(attribute:"risk_factor",value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2015/12/08");

  script_set_attribute(attribute:"plugin_type",value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2015-2023 Tenable Network Security, Inc.");

  script_dependencies("ssl_supported_versions.nasl", "find_service_dtls.nasl");
  script_require_ports("SSL/Supported", "DTLS/Supported");
  script_exclude_keys("global_settings/disable_ssl_cipher_neg");
  exit(0);
}

include("audit.inc");
include("byte_func.inc");
include("ftp_func.inc");
include("global_settings.inc");
include("kerberos_func.inc");
include("ldap_func.inc");
include("misc_func.inc");
include("nntp_func.inc");
include("smtp_func.inc");
include("telnet2_func.inc");
include("ssl_funcs.inc");

if ( get_kb_item("global_settings/disable_ssl_cipher_neg" ) ) exit(1, "Not negotiating the SSL ciphers per user config.");

if(!get_kb_item("SSL/Supported") && !get_kb_item("DTLS/Supported"))
  exit(1, "Neither the 'SSL/Supported' nor the 'DTLS/Supported' flag is set.");

pp_info = get_tls_dtls_ports(fork:TRUE, dtls:TRUE);
port = pp_info["port"];
if (isnull(port))
  exit(1, "The host does not appear to have any TLS or DTLS based services.");

exts = mkword(13172) + mkword(0); # Extension type + empty extension data

if(pp_info["proto"] == "tls")
{
  versions = get_kb_list('SSL/Transport/'+port);

  cipherspec = NULL;

  tls10 = tls11 = tls12 = 0;
  if(! isnull(versions))
  {
    foreach var encap (versions)
    {
      if (encap == ENCAPS_TLSv1)              tls10 = 1;
      else if (encap == COMPAT_ENCAPS_TLSv11) tls11 = 1;
      else if (encap == COMPAT_ENCAPS_TLSv12) tls12 = 1;
    }
  }

  if(!(tls10 || tls11 || tls12))
    exit(0, 'The ' + pp_info["l4_proto"] + ' service listening on port ' + port + ' does not appear to support TLSv1.0 or above.');

  # use latest version available
  if (tls12)       version = COMPAT_ENCAPS_TLSv12;
  else if (tls11)  version = COMPAT_ENCAPS_TLSv11;
  else if (tls10)  version = ENCAPS_TLSv1;

  cipherspec = get_valid_cipherspec_for_encaps(encaps:version, ciphers:ciphers);
  recs = get_tls_server_response(port:port, encaps:version, cipherspec:cipherspec, exts:exts);
}
else if(pp_info["proto"] == "dtls")
{
  cipherspec = dtls10_ciphers;

  version = COMPAT_ENCAPS_TLSv11;
  foreach encap(versions)
  {
    if(encap == COMPAT_ENCAPS_TLSv12)
    {
      version = COMPAT_ENCAPS_TLSv12;
      cipherspec = dtls12_ciphers;
      break;
    }
  }

  recs = get_dtls_server_response(port:port, encaps:version, cipherspec:cipherspec, exts:exts);
}
else
  exit(1, "A bad protocol was returned from get_tls_dtls_ports(). (" + pp_info["port"] + "/" + pp_info["proto"] + ")");

report = FALSE;

info = ssl_find(
  blob:recs,
  'content_type', SSL3_CONTENT_TYPE_HANDSHAKE,
  'handshake_type', SSL3_HANDSHAKE_TYPE_SERVER_HELLO
);

npnprotos = info['extension_next_protocol_negotiation'];
if (!isnull(npnprotos))
{
  foreach var proto (npnprotos)
    set_kb_item(name:"SSL/NPN/" + port, value:proto);
  report = '\n  ' + join(npnprotos, sep:'\n  ');
}

if(report)
{
  report = '\nNPN Supported Protocols: \n' + report + '\n';
  security_report_v4(port:port, extra:report, proto:pp_info["l4_proto"], severity:SECURITY_NOTE);
}
else
  exit(0, "No NPN extension protocols detected on " + pp_info["l4_proto"] + " port " + port + ".");
