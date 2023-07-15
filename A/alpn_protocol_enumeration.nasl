#TRUSTED 5e06c266243f7c2c62316b4d24ffcd253c297e9f03f07ede2e9ef6cb96a59d7a952c66131c135b6b11647355c30b9ededac217affea71383b9c00478cb4be740db44775fcd7706ccafd1ca0deddcf302444a74d9aac40a19c96f18a9ad5e7d3b7d676175743a2ad3b776ffa378de316a96085296ecb1dbf68f60e86e2e883b806d18ce649cf2c33c9c05f42a32f5532bc1b0abfdacb46b76d2877f2a3cfafeb90cd694f3f6b651624ae49b9f73c85cb9ea40e497a63c76a7a37f74183416b9a18392979bb6edd245ce5fe439b09febd253938e29b57ac37481ae6f8a569294196216e80fd2dccd1a75ab38520289416ffb0c90354761a77c0fd915eaca668b7b61d18e8a9f3bdfd2a8a1bee0d02be590f76bba50b47087edc44acb0f3fc02d5ab2cd834a351a25fd08b5900a39b224205eee02e45585e10ba3242414ca293eab6dfe3eb54901dc74a4da37391ecdea8043219687cbb03705f40a01be4948700528e516848c340896c0de599783589051e534a365d7eb1a0139a6c69a3d739db8bd645f53283ea3a799ae72a0679d0a49e86d0c2c9ce28e47ede34eaeae6970e29d33408c4b93c2affa09c62140bafea3bccac192df81b1567fcb885bb6610ad4defe00228aeecf19e27e0ab7032869cd7641e2d113ec5f2b43a973ac68588abfd087fdbc8484c9ee77434794d8541e8e758b70470ae9d6873945042f36b3a67c
#TRUST-RSA-SHA256 724216a192da67b651bfef2a7b1564fcfd52f0fa62949cfdebebad468bf865318a89513bebf375212024c5d5c19c7a0ff0ddb381927cc0e5a18d503878bb59ae5a4f4025825222f6ebee10049e85e65b8c3c17672e0fdaf2b1b65a131e10f02193336047028602589aac279f6bc46b7d3711c1b6828313584797541371989c29d6a3426148627db8a36f1efcefa6e2d7e545a7b01e88b57be64657e7ddf046102b389d19cdd91eb74c03d72a9e99b68cde9cb5f43d65798a20bebd305b52647ed4b175d85e4169169e5422f94dce8d12e551f4795cc9e3fadf69159306efeb06f695c74c63ba1027cdfc36983547304c0b99d452442442c529813f2b923bdf6e3cae2006b5d63b1103cd85c3e1fd9f9e55567c80ca398765bd804d59073df6c3087596569f15448edee96b7de9c1ee1dc2a652ad46150226db5163eef353e8e29564c46e5d142a069f2a28a5abef0b9b59c40b647eb6d399363d44d650fa7d7844777e00bd5d5c38a399b5193001cd9336a58ed85835281e205db85c3e5a7fb00b6fc05e23a230a76707cd8c88b9a28a5f76aebb0f82b20a3e1764be0a7b808b28105f57de58ec6b5b3ae2e5088620b7256a3150a427499d99efe3fd2d9cda66af859ea86fcce9d6290b80bd113f73caf74e1cc901515127ea64334b63974335eb40247f98dd75a9c99f49a04b51524c27a741be023982840339bf67394d28b6
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(84821);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/07/10");

  script_name(english:"TLS ALPN Supported Protocol Enumeration");
  script_summary(english:"Enumerates TLS ALPN supported protocols.");

  script_set_attribute(attribute:"synopsis",value:
"The remote host supports the TLS ALPN extension.");
  script_set_attribute(attribute:"description",value:
"The remote host supports the TLS ALPN extension. This plugin
enumerates the protocols the extension supports.");
  script_set_attribute(attribute:"see_also",value:"https://tools.ietf.org/html/rfc7301");
  script_set_attribute(attribute:"solution",value:"n/a");
  script_set_attribute(attribute:"risk_factor",value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2015/07/17");

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
include("rsync.inc");
include("ssl_funcs.inc");

function alpn_ext()
{
  local_var item, proto_list, proto_list_str;

  proto_list_str = '';
  proto_list = _FCT_ANON_ARGS[0];

  foreach item (proto_list)
    proto_list_str += mkbyte(strlen(item)) + item;

  return  mkword(16)  +  # extension type
          mkword(strlen(proto_list_str)+2) +
          mkword(strlen(proto_list_str)) +
          proto_list_str;
}

if ( get_kb_item("global_settings/disable_ssl_cipher_neg" ) ) exit(1, "Not negotiating the SSL ciphers per user config.");

if(!get_kb_item("SSL/Supported") && !get_kb_item("DTLS/Supported"))
  exit(1, "Neither the 'SSL/Supported' nor the 'DTLS/Supported' flag is set.");

pp_info = get_tls_dtls_ports(fork:TRUE, dtls:TRUE);
port = pp_info["port"];
if (isnull(port))
  exit(1, "The host does not appear to have any TLS or DTLS based services.");

if(pp_info["proto"] == "tls")
{
  # https://www.iana.org/assignments/tls-extensiontype-values/tls-extensiontype-values.xhtml#alpn-protocol-ids
  protocols = make_list("http/1.1", "spdy/1", "spdy/2", "spdy/3", "h2",

  # these are additional non-iana registered protocols that are used in mod_h2, IIS 10, or
  # sent by firefox/chrome
                        "spdy/3.1", "h2-14", "h2-15", "h2-16");

  versions = get_kb_list('SSL/Transport/'+port);

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
    exit(0, 'The SSL-based service listening on ' + pp_info["l4_proto"] + ' port '+port+' does not appear to support TLSv1.0 or above.');

  # use latest version available
  if (tls12)       version = COMPAT_ENCAPS_TLSv12;
  else if (tls11)  version = COMPAT_ENCAPS_TLSv11;
  else if (tls10)  version = ENCAPS_TLSv1;

  cipherspec = get_valid_cipherspec_for_encaps(encaps:version, ciphers:ciphers);
}
else if(pp_info["proto"] == "dtls")
{
  # the following are alpn protocol ids for STUN and TURN - ietf RFC-7443
  # https://tools.ietf.org/html/rfc7443
  # and WebRTC https://tools.ietf.org/html/draft-ietf-rtcweb-alpn-04
  protocols = make_list("stun.nat-discovery", "stun.turn", "webrtc", "c-webrtc");

  versions = get_kb_list('DTLS/Transport/' + port);
  if(isnull(versions))
    exit(0, 'The DTLS service listening on ' + pp_info["l4_proto"] + ' port ' + port + ' does not appear to use a supported version.');

  version = COMPAT_ENCAPS_TLSv11;
  cipherspec = dtls10_ciphers;
  foreach encap(versions)
  {
    if(encap == COMPAT_ENCAPS_TLSv12)
    {
      version = COMPAT_ENCAPS_TLSv12;
      cipherspec = dtls12_ciphers;
      break;
    }
  }
}
else
  exit(1, "A bad protocol was returned from get_tls_dtls_ports(). (" + pp_info["port"] + "/" + pp_info["proto"] + ")");

report = '';

foreach var protocol (protocols)
{
  exts = alpn_ext(make_list(protocol));
  if(pp_info["proto"] == "tls")
    recs = get_tls_server_response(port:port, encaps:version, cipherspec:cipherspec, exts:exts);
  else
    recs = get_dtls_server_response(port:port, encaps:version, cipherspec:cipherspec, exts:exts);

  if(!recs) break;

  info = ssl_find(
    blob:recs,
    'content_type', SSL3_CONTENT_TYPE_HANDSHAKE,
    'handshake_type', SSL3_HANDSHAKE_TYPE_SERVER_HELLO
  );

  if (!isnull(info['extension_alpn_protocol']) && info['extension_alpn_protocol'] == protocol)
  {
    set_kb_item(name:"SSL/ALPN/" + port, value:info['extension_alpn_protocol']);
    report += '\n  ' + info['extension_alpn_protocol'];
  }
}

if(report != '')
  security_report_v4(port:port, proto:pp_info["l4_proto"], severity:SECURITY_NOTE, extra:report);
else
  exit(0, "No ALPN extension protocols detected on " + pp_info["l4_proto"] + " port " + port + ".");
