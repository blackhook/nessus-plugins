#TRUSTED 2d02cf267ec78d4f1ff5bedd60ea5daf76559a39f01b048008f4b18d536f0017bbf6d1623ca1ee7f090eec25b58857608b5973b2ef8b8f915d2224274ffb5ed8b77addb9ac6904c9eff404c5f09c106f79e76b0a04b1678a93bae8cf4cbc002034d380b3e555a0621e6b3f2b498dc0846c55056a2363e4b33d1e85b88f2370b5b8c3387b44adf42c344c68c4d33f7b02d0a7689275a7ba21de3255718487e2723328bd659f9753cc3b8206f48721e81d2d70f76aac69ea204012abbb5016a95f311183b0edf2f13deda7bff62ef08e2db1bfa84752d47c48437d16fb8521d5e77c99c5da3870f34145ed4f0481468ec6ea4ca60cbd9516954fabf2031ed3b5c32718aeb094726472ed6a0121a8941d977673484ca9852032eaca85b8bcb5299e815c44d3df4bc2f14a8651aa7c7296ffb4044fe2886edb5c1b513caedaf41744b46276c5d9f61d16c8bc011ab8a8c93d4d1668eef4b61f8969c1dc6bbb321b72b8572e937eee9ce6ff58d84830829077eac8f432577bfaf1bfa0080df851852e35fcbf8886fd5a401b9f11d7c662f888ed7a041cbeca5f2c87724813cfe6a85c3574e1fc95c9113443a336d63235f942383358372ecb2d35781fd0c25b361621986487adba9da9627e71b09aefdae4b9e16eddb9a7336c1a669058838908b917a62373b1031f26e91666f86f146625c81bce58cd1696d72f1292ce4e12de5239
#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include("compat.inc");

if (description)
{
  script_id(62564);
  script_version("1.15");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_name(english:"TLS Next Protocols Supported");

  script_set_attribute(attribute:"synopsis", value:
"The remote service advertises one or more protocols as being supported
over TLS.");
  script_set_attribute(attribute:"description", value:
"This script detects which protocols are advertised by the remote
service to be encapsulated by TLS connections.

Note that Nessus did not attempt to negotiate TLS sessions with the
protocols shown.  The remote service may be falsely advertising these
protocols and / or failing to advertise other supported protocols.");
  script_set_attribute(attribute:"see_also", value:"https://tools.ietf.org/html/draft-agl-tls-nextprotoneg-04");
  script_set_attribute(attribute:"see_also", value:"https://technotes.googlecode.com/git/nextprotoneg.html");
  script_set_attribute(attribute:"solution", value:
"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2012/10/16");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"General");

  script_copyright(english:"This script is Copyright (C) 2012-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssl_supported_versions.nasl", "find_service_dtls.nasl");
  script_require_ports("SSL/Supported", "DTLS/Supported");

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
include("ssl_funcs.inc");
include("telnet2_func.inc");
include("rsync.inc");
include("audit.inc");

if(!get_kb_item("SSL/Supported") && !get_kb_item("DTLS/Supported"))
  exit(1, "Neither the 'SSL/Supported' nor the 'DTLS/Supported' flag is set.");

set_byte_order(BYTE_ORDER_BIG_ENDIAN);

# Get a port to operate on, forking for each one.
pp_info = get_tls_dtls_ports(fork:TRUE, dtls:TRUE, check_port:TRUE);
port = pp_info["port"];
if (isnull(port))
  exit(1, "The host does not appear to have any TLS or DTLS based services.");

# If it's encapsulated already, make sure it's a type we support.
if(pp_info["proto"] == "tls")
  encaps = get_kb_item("Transports/TCP/" + port);
else if(pp_info["proto"] == "dtls")
  encaps = get_kb_item("Transports/UDP/" + port);
else
  exit(1, "A bad protocol was returned from get_tls_dtls_ports(). (" + pp_info["port"] + "/" + pp_info["proto"] + ")");

if (encaps > ENCAPS_IP && (encaps < ENCAPS_SSLv2 || encaps > COMPAT_ENCAPS_TLSv12))
  exit(1, pp_info["l4_proto"] + " port " + port + " uses an unsupported encapsulation method.");

# Determine whether this port uses StartTLS.
starttls = get_kb_list("*/" + port + "/starttls");
starttls = (!isnull(starttls) && max_index(starttls));

# Choose which transports to test.
if (thorough_tests)
{
  versions = make_list(
    ENCAPS_TLSv1,
    COMPAT_ENCAPS_TLSv11,
    COMPAT_ENCAPS_TLSv12
  );
}
else
{
  if(pp_info["proto"] == "tls")
    versions = get_kb_list_or_exit("SSL/Transport/" + port);
  else
    versions = get_kb_list_or_exit("DTLS/Transport/" + port);
}

# This is the Next Protocol Negotiation extension that asks the server to list
# its supported protocols.
npn =
  mkword(13172) + # Extension type
  mkword(0);      # Extension length

# Add on an SNI extension if it makes sense to
host = get_host_name();
if (host != get_host_ip() && host != NULL)
  npn += tls_ext_sni(hostname:host);

# Determine which next protocols are supported.
supported = make_list();
foreach encaps (versions)
{
  if (starttls_svc && encaps < ENCAPS_TLSv1) continue;

  if(pp_info["proto"] == "dtls")
  {
    if(encaps == COMPAT_ENCAPS_TLSv11)
      ssl_ver = raw_string(0xfe, 0xff);
    else if(encaps == COMPAT_ENCAPS_TLSv12)
      ssl_ver = raw_string(0xfe, 0xfd);
    else
      continue;
  }
  else
  {
    # This is a TLS extension, so skip SSL.
    if (encaps == ENCAPS_SSLv2) continue;
    else if (encaps == ENCAPS_SSLv3) continue;
    else if (encaps == ENCAPS_TLSv1) ssl_ver = raw_string(0x03, 0x01);
    else if (encaps == COMPAT_ENCAPS_TLSv11) ssl_ver = raw_string(0x03, 0x02);
    else if (encaps == COMPAT_ENCAPS_TLSv12) ssl_ver = raw_string(0x03, 0x03);
  }

  exts = npn;
  if (encaps == COMPAT_ENCAPS_TLSv12)
    exts += tls_ext_ec() + tls_ext_ec_pt_fmt() + tls_ext_sig_algs();

  var test_mode = FALSE;

  if(pp_info["proto"] == "dtls")
  {
    if (get_kb_item("TEST_dtls_in_flatline"))
      test_mode = TRUE;

    recs = get_dtls_server_response(port:port, encaps:encaps, exts:exts, test_mode:test_mode);
  }
  else
  {
    recs = get_tls_server_response(port:port, encaps:encaps, exts:exts);
  }


  # Find and parse the ServerHello record.
  rec = ssl_find(
    blob:recs,
    "content_type", SSL3_CONTENT_TYPE_HANDSHAKE,
    "handshake_type", SSL3_HANDSHAKE_TYPE_SERVER_HELLO
  );
  if (isnull(rec)) continue;

  # Ensure that the SSL version is what we expect.
  if (rec["version"] != getword(blob:ssl_ver, pos:0)) continue;

  # Merge in the listed protocols to our running list.
  protocols = rec["extension_next_protocol_negotiation"];
  if (!isnull(protocols))
    supported = make_list(supported, protocols);
}

supported = list_uniq(supported);
if (max_index(supported) == 0)
  exit(0, pp_info["l4_proto"] + " port " + port + " did not list any protocols as supported.");

# Stash the list of supported protocols in the KB for future use.
if(pp_info["proto"] == "tls")
{
  kb_base = "SSL/Protocols/";
  desc_proto = "SSL / TLS";
}
else if(pp_info["proto"] == "dtls")
{
  kb_base = "DTLS/Protocols/";
  desc_proto = "DTLS";
}

foreach name (supported)
{
  set_kb_item(name:kb_base + port, value:name);
}

# Report our findings.
report =
  '\nThe target advertises that the following protocols are' +
  '\nsupported over ' + desc_proto + ':' +
  '\n' +
  '\n  ' + join(sort(supported), sep:'\n  ') +
  '\n';

security_report_v4(port:port, extra:report, proto:pp_info["l4_proto"], severity:SECURITY_NOTE);

