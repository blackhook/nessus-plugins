#TRUSTED 1e291ae0241e359c4b2a8b09b1ce8628c4b4c9d1ec15af2073127ceb878c233686a8040ed94da046d0069af915126c9927f67a2a92f2fd392a3404426fa53e68cfc8e056c3b768f940fbd111f69b07f6918a52fa55099bcb12461e99ce292a5ac22f7ea6adfc30b61cb422cdeb5023c2a65ddefff689523c75f4bd16f93a577db89c79756d0122038e303a4dc0f0a4f69db7e43a714295670c2be26f8645775b11ffe089edf271b52a0a58e1b3fa241199a2d7f94282d346b17fc97dc259d828e8084f233bf407e4c84735512818579a74d6b08b86b1936d2e358063e7323ece4f74aee8f6aa8886bce2a72e5c556f0f0ecde1566b42c3c5eaf50d0bf9980f3319b2b1d78043098a05b64db926eb420ed2ca5c6a960d2ba45b66571f0c6578a24bee7d0f75eceeea747c8d0f3168c426292f300643a600c2846751825b21f26790f21e6f2e12cdd4c6b4e82b0e623ef9965944380c820b0c29d998852305b2352cb230b4f4c373b18bfddf2ae407eecde09131caea867b71287fe0dc4b3270f038f99b2c6eecde7d3f7e8b93b590b57f729378428d32cbd31fcb3bd6f2bc4aa193d47558149a5f258999a45d2c89540fc266d8e31a11370a45eb58f67925a7c238d7c34d53d54996bb5e74af9560fbd1e99cfbd3e2283f7c606aa95ff2b5065f324b41949302d783c7425e8e0c1c582e5be82e82ad7a7eb439955c1be73ca139
#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include("compat.inc");

if (description)
{
  script_id(62563);
  script_version("1.16");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_name(english:"SSL Compression Methods Supported");

  script_set_attribute(attribute:"synopsis", value:
"The remote service supports one or more compression methods for SSL
connections.");
  script_set_attribute(attribute:"description", value:
"This script detects which compression methods are supported by the
remote service for SSL connections.");
  script_set_attribute(attribute:"see_also", value:"http://www.iana.org/assignments/comp-meth-ids/comp-meth-ids.xml");
  script_set_attribute(attribute:"see_also", value:"https://tools.ietf.org/html/rfc3749");
  script_set_attribute(attribute:"see_also", value:"https://tools.ietf.org/html/rfc3943");
  script_set_attribute(attribute:"see_also", value:"https://tools.ietf.org/html/rfc5246");
  script_set_attribute(attribute:"solution", value:
"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2012/10/16");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"General");

  script_copyright(english:"This script is Copyright (C) 2012-2022 Tenable Network Security, Inc.");

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

# Determine whether this port uses StartTLS.
starttls = get_kb_list("*/" + port + "/starttls");
starttls = (!isnull(starttls) && max_index(starttls));

# Choose which transports to test.
if (thorough_tests)
{
  versions = make_list(
    ENCAPS_SSLv2,
    ENCAPS_SSLv3,
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

# Determine which compressors are supported.
supported = make_array();
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

  # Iterate over each possible compressor.
  for (id = 1; id < 256; id++)
  {
    # Only test known compressors unless we're being thorough and not using DTLS.
    if ((pp_info["proto"] == "dtls" || !thorough_tests) && isnull(compressors[id])) continue;

    # Skip compressors that we already know are supported.
    if (supported[id]) continue;

    # Note that we must always send the NULL (0x00) compressor.
    cmps = raw_string(id);
    if (id != 0x00)
      cmps += raw_string(0x00);

    exts = "";
    if (encaps >= ENCAPS_TLSv1)
    {
      host = get_host_name();
      if (host != get_host_ip() && host != NULL)
        exts += tls_ext_sni(hostname:host);

      # Include extensions for TLS 1.2 ciphers
      if (encaps == ENCAPS_TLSv1_2)
        exts += tls_ext_ec() + tls_ext_ec_pt_fmt() + tls_ext_sig_algs();
    }

    if (exts == "")
      exts = NULL;


    if(pp_info["proto"] == "dtls")
      recs = get_dtls_server_response(port:port, encaps:encaps, exts:exts, cmps:cmps);
    else
      recs = get_tls_server_response(port:port, encaps:encaps, exts:exts, cmps:cmps);

    # Find and parse the ServerHello record.
    rec = ssl_find(
      blob:recs,
      "content_type", SSL3_CONTENT_TYPE_HANDSHAKE,
      "handshake_type", SSL3_HANDSHAKE_TYPE_SERVER_HELLO
    );
    if (isnull(rec)) continue;

    # Ensure that the SSL version is what we expect.
    if (rec["version"] != getword(blob:ssl_ver, pos:0)) continue;

    # Ensure that the compression method matches what we sent.
    if (rec["compression_method"] != id) continue;

    supported[id] = TRUE;
  }
}

supported = keys(supported);
if (max_index(supported) == 0)
  exit(0, pp_info["l4_proto"] + " port " + port + " does not appear to have any compressors enabled.");

# Stash the list of supported compressors in the KB for future use, and convert
# to integers.
for (i = 0; i < max_index(supported); i++)
{
  id = int(supported[i]);
  supported[i] = id;
  if(pp_info["proto"] == "tls")
    set_kb_item(name:"SSL/Compressors/" + port, value:id);
  else
    set_kb_item(name:"DTLS/Compressors/" + port, value:id);
}

# Report our findings.
names = make_list();
foreach id (sort(supported))
{
  name = compressors[id];
  if (isnull(name))
  {
    if (id <= 63)
      usage = "IETF Standards Track protocols";
    else if (id <= 223)
      usage = "non-Standards Track";
    else
      usage = "private use";

    name = "Unknown, reserved for " + usage;
  }
  name += " (" + hex(id) + ")";

  names = make_list(names, name);
}

if (max_index(names) == 1)
  s = " is ";
else
  s = "s are ";

report =
  '\nNessus was able to confirm that the following compression method' + s +
  '\nsupported by the target :' +
  '\n' +
  '\n  ' + join(names, sep:'\n  ') +
  '\n';

security_report_v4(port:port, extra:report, proto:pp_info["l4_proto"], severity:SECURITY_NOTE);

