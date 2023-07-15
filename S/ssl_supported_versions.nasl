#TRUSTED 0b8d7cba22c7ccd26215582db69ddd843b9a4500d3be5664f2d85fe5f5bc0fb2042149e61eb5760336c6b936c2c1673c313811ca8f0ee346ced9452162b23b5847c2db9adbcb591869f2202c297d381f5b653c3a1f2b904ab0f873ac79fc4c6c42efe551ede03f9e37a254c95a6538747aec037a28bc208f84aab1ad0321fba58fe76c93ee113608628ae57d7fcdbb79b23fa125ead687bfd2644f3c3c6f677c3b6bb46baf47f905d9acc3343a16a82592aad79baa1f0c9fa3c731182b3316e0b2ec636001b11db53592d94f0518bfb4a4c3cbf9e000916dc7b7ab741642bdc528f740f845df68c2375fdad4f2ff07e3fe9bcd65a4b44036329ac96e107c94e90abb3a7f5f1481c9c41dd0b15512d7800e2d1ded8e44ae4230e5547850afb6f0dc9168cc48e444cb43d0e47fe1881f3cf901a327404886bca8552cd760e806a55f4d44b7da75d4be4e96c24a034a1dc54da67f158e265b353d5124423003f58ca56ddf0b5b072fedf7da456e19671548f657c8ca03b0eaaa03b42cdb78f88891309fd66173b6c10b15345a2dac5ebdae36b0daf4cc02e158d3ba9444a2b78320a4aafd65ab2d2d04219950728178f1281b59cef5d5c39b56cde1e06194bd03dd7406494ff5d04921d843ab236a1151e06c35dfe8b93210ae9f6e004b2a8264dc249b1eb6e13e427fae2a0225b7d875b0396dedb46290d12ebf7f19761420548b
#TRUST-RSA-SHA256 2f092003c85b506b3d797d188059818037f0020202e79c699335260309ce1276fd261b78af708ba61e20a79662d50535af05a8fa5e7911b361309f78937627bf19817b68479070e4da94f9b2709a96f093c478fc325a1361401f8ba0e20e35b1dc7ba7d528f8bba8da1009b69817bef9c9cc65c54634005e36c037d4c84c0cae27c2e8effe51af05e6505aa16f88375bed25d142a48b1ebffc4470f183b5ec29e895a48a4da70b507eaabe6006a0459cf07c7c30961ff492fb838879be512b55a7009a34e3f6244f09fbfb891219946bb4ad10cea6188000fdcf03a01dda0d24a917976e6bc3edd465a77c8752fca390a2321a3e0d93bf8db852b9b4e5f778c3f15edc7daf9807ea65fa833cd4cf9430d7220dbadd46f93054c615cb01d3dc6f1f479eb13d25680bb876e9a6eaa46b4f1afc7c10878540be37d2a3ebea63c8a8173fb7583a59307ba071831eba4a7ef509df21a7da5632d661cb9d5bbd44580d03eeaf4d4fba2e8d6f0c50928c00b958ac544fa025e455eea4ff72e543099a3336925be4b83a2a66632c52160e6b68b8efac788e27561928bb1a85fd5a2bc4cbbeb07026d0cff88ee8dab0fcc19043c9969aff1189b234faf7c2ee41d7c3aeb9f946549e92e341fd233eadd135834325b9f21deb859bf7436a472a2021f2326e31183460e6bbced73218cb15c1c7a6c2e07e15eaef0fd593b18032367dc27c3f
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(56984);
  script_version("1.35");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/07/10");

  script_name(english:"SSL / TLS Versions Supported");
  script_summary(english:"Checks which SSL / TLS versions are supported.");

  script_set_attribute(attribute:"synopsis", value:
"The remote service encrypts communications.");
  script_set_attribute(attribute:"description", value:
"This plugin detects which SSL and TLS versions are supported by the
remote service for encrypting communications.");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2011/12/01");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"General");

  script_copyright(english:"This script is Copyright (C) 2011-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies(
      "find_service1.nasl",
      "apache_SSL_complain.nasl",
      "acap_starttls.nasl",
      "amqp_starttls.nasl",
      "ftp_starttls.nasl",
      "imap4_starttls.nasl",
      "ldap_starttls.nasl",
      "mssql_starttls.nasl",
      "nntp_starttls.nasl",
      "nut_starttls.nasl",
      "pop3_starttls.nasl",
      "rdp_ssl.nasl",
      "smtp_starttls.nasl",
      "telnet_starttls.nasl",
      "xmpp_starttls.nasl",
      "ircd_starttls.nasl",
      "rsync_starttls.nasl",
      "postgresql_starttls.nasl",
      "vmware_902_starttls.nasl"
    );

  script_exclude_keys("global_settings/disable_test_ssl_based_services", "global_settings/disable_ssl_cipher_neg");
  exit(0);
}

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
include("audit.inc");
include("rsync.inc");

global_var openssl_ciphers;

if (get_kb_item("global_settings/disable_test_ssl_based_services"))
  exit(1, "Not testing SSL based services per user config.");

if ( get_kb_item("global_settings/disable_ssl_cipher_neg" ) ) exit(1, "Not negotiating the SSL ciphers, per user config");

openssl_ciphers = make_array(
  "SSLv2", raw_string(
    0x07, 0x00, 0xc0,
    0x05, 0x00, 0x80,
    0x03, 0x00, 0x80,
    0x01, 0x00, 0x80,
    0x06, 0x00, 0x40,
    0x04, 0x00, 0x80,
    0x02, 0x00, 0x80
  ),
  "SSLv23", raw_string(
    0x00, 0x00, 0x89,
    0x00, 0x00, 0x88,
    0x00, 0x00, 0x87,
    0x00, 0x00, 0x84,
    0x00, 0x00, 0x46,
    0x00, 0x00, 0x45,
    0x00, 0x00, 0x44,
    0x00, 0x00, 0x41,
    0x00, 0x00, 0x3a,
    0x00, 0x00, 0x39,
    0x00, 0x00, 0x38,
    0x00, 0x00, 0x35,
    0x00, 0x00, 0x34,
    0x00, 0x00, 0x33,
    0x00, 0x00, 0x32,
    0x00, 0x00, 0x2f,
    0x00, 0x00, 0x1b,
    0x00, 0x00, 0x1a,
    0x00, 0x00, 0x19,
    0x00, 0x00, 0x18,
    0x00, 0x00, 0x17,
    0x00, 0x00, 0x16,
    0x00, 0x00, 0x15,
    0x00, 0x00, 0x14,
    0x00, 0x00, 0x13,
    0x00, 0x00, 0x12,
    0x00, 0x00, 0x11,
    0x00, 0x00, 0x0a,
    0x00, 0x00, 0x09,
    0x00, 0x00, 0x08,
    0x00, 0x00, 0x06,
    0x00, 0x00, 0x05,
    0x00, 0x00, 0x04,
    0x00, 0x00, 0x03,
    0x07, 0x00, 0xc0,
    0x06, 0x00, 0x40,
    0x04, 0x00, 0x80,
    0x03, 0x00, 0x80,
    0x02, 0x00, 0x80,
    0x01, 0x00, 0x80,
    0x00, 0x00, 0xff
  ),
  "SSLv3", raw_string(
    0xc0, 0x14,
    0xc0, 0x0a,
    0x00, 0x39,
    0x00, 0x38,
    0x00, 0x88,
    0x00, 0x87,
    0xc0, 0x0f,
    0xc0, 0x05,
    0x00, 0x35,
    0x00, 0x84,
    0xc0, 0x12,
    0xc0, 0x08,
    0x00, 0x16,
    0x00, 0x13,
    0xc0, 0x0d,
    0xc0, 0x03,
    0x00, 0x0a,
    0xc0, 0x13,
    0xc0, 0x09,
    0x00, 0x33,
    0x00, 0x32,
    0x00, 0x9a,
    0x00, 0x99,
    0x00, 0x45,
    0x00, 0x44,
    0xc0, 0x0e,
    0xc0, 0x04,
    0x00, 0x2f,
    0x00, 0x96,
    0x00, 0x41,
    0x00, 0x07,
    0xc0, 0x11,
    0xc0, 0x07,
    0xc0, 0x0c,
    0xc0, 0x02,
    0x00, 0x05,
    0x00, 0x04,
    0x00, 0x15,
    0x00, 0x12,
    0x00, 0x09,
    0x00, 0x14,
    0x00, 0x11,
    0x00, 0x08,
    0x00, 0x06,
    0x00, 0x03,
    0x00, 0xff
  )
);

function supports_TLS13(port)
{
  local_var data, rec, chello, sock;

  chello = tls13_client_hello();

  sock = open_sock_ssl(port);
  if (!sock) return FALSE;

  send(socket:sock, data:chello);

  data = recv_ssl(socket:sock, hard_timeout:TRUE);
  close(sock);

  # Server hello
  rec = ssl_find(
    blob:data,
    'content_type', SSL3_CONTENT_TYPE_HANDSHAKE,
    'handshake_type', SSL3_HANDSHAKE_TYPE_SERVER_HELLO
  );
  if ( !isnull(rec) )
  {
    # check our server version is 3,3 and our extension supported version is TLS 1.3
    if (rec['handshake_version'] == 0x0303 && rec['extension_supported_versions'][0] == 0x0304)
      return TRUE;
  }

  return FALSE;
}

function supports(encaps, port)
{
  var cipher, cipherspec, helo, i, limit, rec, recs, sock, v2;
  var version, exts, host, version_ciphers, sni;
  var sni_alert = sni = FALSE;

  # Both SSLv2 and SSLv23 clients begin by sending an record in SSLv2
  # format.
  v2 = (encaps == ENCAPS_SSLv2 || encaps == ENCAPS_SSLv23);

  if (encaps == ENCAPS_SSLv2) version = raw_string(0x00, 0x02);
  else if (encaps == ENCAPS_SSLv3) version = raw_string(0x03, 0x00);
  else if (encaps == ENCAPS_TLSv1) version = raw_string(0x03, 0x01);
  else if (encaps == COMPAT_ENCAPS_TLSv11) version = raw_string(0x03, 0x02);
  else if (encaps == COMPAT_ENCAPS_TLSv12) version = raw_string(0x03, 0x03);

  # For most encapsulation types we first try connecting with all
  # ciphers, and then try with a OpenSSL's default set. For SSLv23 we
  # need an extra iteration since trying all ciphers needs to be done
  # in both SSLv3 and TLSv1 upgrade modes to detect all server
  # configurations.
  limit = 2;
  if (encaps == ENCAPS_SSLv23)
    limit += 1;

  for (i = 1; i <= limit; i++)
  {
    # SSLv23 goes through the following phases:
    #
    # 1) SSLv2 upgradeable to SSLv3 with all known ciphers.
    # 2) SSLv2 upgradeable to TLSv1 with all known ciphers.
    # 3) SSLv2 upgradeable to TLSv1 with OpenSSL's default ciphers.
    if (encaps == ENCAPS_SSLv23)
    {
      if (i == 1)
        version = raw_string(0x03, 0x00);
      else
        version = raw_string(0x03, 0x01);
    }

    version_ciphers = get_valid_ciphers_for_encaps(encaps:encaps, ciphers:ciphers);

    if (i != limit)
    {
      # See if the server supports this type of SSL by sending a
      # ClientHello with every possible cipher spec.
      cipherspec = "";
      foreach cipher (sort(keys(version_ciphers)))
      {
        if (
          (encaps == ENCAPS_SSLv2 && "SSL2_" >< cipher) ||
          (
            encaps == ENCAPS_SSLv23 &&
            (
              "SSL2_" >< cipher ||
              (i == 0 && "SSL3_" >< cipher) ||
              (i == 1 && "TLS1_" >< cipher)
            )
          ) ||
          # ciphers for >=SSLv3
          (
            encaps >= ENCAPS_SSLv3 &&
            encaps <= COMPAT_ENCAPS_TLSv12 &&
            strlen(ciphers[cipher]) == 2
          )
        )
        {
          # Normally, we can just add the cipher to the cipherspec,
          # but in SSLv23 we have to zero-extend the SSLv3 and TLSv1
          # ciphers to match the SSLv2 format.
          if (encaps == ENCAPS_SSLv23 && "SSL2_" >!< cipher)
            cipherspec += raw_string(0x00);
          cipherspec += ciphers[cipher];
        }
      }
    }
    else
    {
      # Certain SSL implementations, when sent a ClientHello with a
      # number of ciphers past some threshold, simply close the
      # socket. If we see this, try connecting with the default list
      # that OpenSSL uses.
      if (encaps == ENCAPS_SSLv2)
        cipherspec = openssl_ciphers["SSLv2"];
      else if (encaps == ENCAPS_SSLv23)
        cipherspec = openssl_ciphers["SSLv23"];
      else if (encaps == ENCAPS_SSLv3)
        cipherspec = openssl_ciphers["SSLv3"];
      else
        cipherspec = get_openssl_cipherspec(encaps:encaps);
    }


    # In some SSL implementations, EC-based cipher suites require
    # a supported named curve in ClientHello for it to return a
    # ServerHello, so we will send EC extensions, claiming
    # to support all curves and EC point formats.
    if (encaps >= ENCAPS_TLSv1 && encaps <= COMPAT_ENCAPS_TLSv12)
    {
      exts = tls_ext_ec() + tls_ext_ec_pt_fmt();

      # Add on an SNI extension if it makes sense to
      host = get_host_name();
      if (host != get_host_ip() && host != NULL && !sni_alert)
      {
        sni = TRUE;
        exts += tls_ext_sni(hostname:host);
      }

      if(encaps == COMPAT_ENCAPS_TLSv12)
        exts += tls_ext_sig_algs();
    }
    else exts = NULL;


    # Manually craft a ClientHello.
    rec = client_hello(
      version    : version,
      cipherspec : cipherspec,
      v2hello    : v2,
      extensions: exts
    );
    if (isnull(rec)) return FALSE;

    # Open a connection to the server.
    sock = open_sock_ssl(port);
    if (!sock) return FALSE;

    # Send the ClientHello.
    send(socket:sock, data:rec);

    # Receive target's response.
    recs = recv_ssl_recs(socket: sock, timeout: 20);
    close(sock);

    # Find the ServerHello record.
    if (encaps == ENCAPS_SSLv2)
    {
      rec = ssl_find(
        blob:recs,
        "content_type", SSL2_CONTENT_TYPE_SERVER_HELLO
      );
    }
    else
    {
      rec = ssl_find(
        blob:recs,
        "content_type", SSL3_CONTENT_TYPE_HANDSHAKE,
        "handshake_type", SSL3_HANDSHAKE_TYPE_SERVER_HELLO
      );

      if(sni)
      {
        var alert = ssl_find(blob:recs, "content_type", SSL3_CONTENT_TYPE_ALERT);
        if(!isnull(alert))
        {
          if(alert['level'] == SSL3_ALERT_TYPE_FATAL &&
             alert['description'] == SSL3_ALERT_TYPE_UNRECOGNIZED_NAME)
          {
            # Try again without SNI
            ssl_dbg(lvl: 1, src:SCRIPT_NAME, msg:'Received alert for unrecognized name,' +
              'retrying without SNI.');
            replace_kb_item(name:"SSL/NO_SNI/" + port, value:TRUE);
            sni_alert = TRUE;
            limit += 1;
          }
        }
      }
    }

    # If we didn't find the record we were looking for, then the
    # server doesn't support this encapsulation method.
    if (isnull(rec)) continue;

    # If we're in SSLv2 mode, we'd like an SSLv2 response. If we're in
    # any other mode, success is indicated by an SSLv3/TLSv1 response
    # with a version number matching our ClientHello.
    if (rec["version"] == getword(blob:version, pos:0))
      return TRUE;
  }

  return FALSE;
}

# All parameters in SSL are big-endian.
set_byte_order(BYTE_ORDER_BIG_ENDIAN);

# Get list of ports that use SSL or StartTLS.
ports = get_ssl_ports();
if (isnull(ports) || max_index(ports) == 0)
  exit(0, "The host does not appear to have any SSL-based services.");

encapsulations = make_array(
  "SSLv2", ENCAPS_SSLv2,
#  "SSLv23", ENCAPS_SSLv23, # XXX-MAK: Disabled due to FPs.
  "SSLv3", ENCAPS_SSLv3,
  "TLSv1.0", ENCAPS_TLSv1,
  "TLSv1.1", COMPAT_ENCAPS_TLSv11,
  "TLSv1.2", COMPAT_ENCAPS_TLSv12
  # note TLS 1.3 is handled sperately below
);

# Test every port for which versions of SSL/TLS are supported.
flag = 0;
foreach var port (ports)
{
  if (!get_port_state(port)) continue;

  supports_tls13 = FALSE;
  versions = make_list();

  # first we check TLS 1.3 separately since it is special
  if (supports_TLS13(port:port))
  {
    versions = make_list(versions, "TLSv1.3");
    set_kb_item(name:"SSL/Transport/" + port, value:COMPAT_ENCAPS_TLSv13);
    supports_tls13 = TRUE;
  }

  # then we check each older version of SSL/TLS.
  foreach var encaps (sort(keys(encapsulations)))
  {
    id = encapsulations[encaps];

    if (!supports(port:port, encaps:id)) continue;

    versions = make_list(versions, encaps);

    set_kb_item(name:"SSL/Transport/" + port, value:id);
    replace_kb_item(name:"Transports/TCP/" + port, value:id);
  }

  #We want this KB to reflect the highest supported version - see find_service.nasl
  if(supports_tls13)
    replace_kb_item(name:"Transports/TCP/" + port, value:id);

  # Combine results from all versions into one report for this port.
  if (max_index(versions) == 0) continue;

  if ( flag == 0 )
  {
	set_kb_item(name:"SSL/Supported", value:TRUE);
	flag = 1;
  }

  report = '\nThis port supports ' + join(versions, sep:"/") + '.\n';
  security_note(port:port, extra:report);
}
if (flag == 0)
{
  if (max_index(ports) > 1)
    plural = "s";
  else
    plural = "";

  exit(0, "No supported TLS versions were detected (port" + plural + ": " + join(ports, sep:", ") + ")");
}

