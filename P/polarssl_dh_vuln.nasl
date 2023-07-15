#TRUSTED 828d17a6cb82bf5b0084eabac071db813e34abac0b2ac99f227d42e1fb9ef86ae80e8ee55e016afbb9d34f97efcb0f0366d868f31cf4b23319f3159d3cf633d6fd66663e541fa1e52126a04cf383e90e6b4ba483c8058b99b68f4632821f6284287f026e26fb0e7d50d75e0e5b54149012060435b435fcf07a900aea98124f15ec0a1b8dd53d18de67a8d9edfd24af3dba84636faaa65a8a33a98de8ca9abaf6b688fe768860803e0d946e9dd5138c2787fa67498bcca3614b33899cdcfbe90109ceff9d39f994d605885cebcdb01ca56c8e7146010d7acb57b4cb37f1f018106aa44256f08e9ac496c0e8fe035c5ea22fe328f8eb12ebc50da9dcc3e84f302ec1e296c24353e2fb1aba4e436fea1087010ffc7beba17762cc3faba0416ca7dfce311d9523dfe0d9e4436be5423c40d592ffe3699cb3000b9cdb97a39b9945d666212f76944cde25cff546507fb961dc29a105a0f23d22781ad118341ae47865ff887e4aae1f6debf097deefd068933478882807a7becea7458b7c012adbec1220ccf62cce7daef6b4da3ab857016e9438eebaa1e5f56f9998dd39b8ae23d0b1f78aa8979cf985dfa6404fd862d70c86aaee79369aebbc68c1c3a37f3709331c193e2298fd32835db2b04db905d503c842a771da9fff21c2cdd4036fef3a897aee7d6c577377ef35e910da61466eac4971f481f13dd5daca9b44ba94e94db175
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(53360);
  script_version("1.35");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/06/12");

  # script_cve_id("CVE-2011-1923");
  # script_bugtraq_id(46670);

  script_name(english:"SSL Server Accepts Weak Diffie-Hellman Keys");
  script_summary(english:"Checks if remote SSL/TLS server accepts Diffie-Hellman public value of 1.");

  script_set_attribute(attribute:"synopsis", value:"The remote SSL/TLS server accepts a weak Diffie-Hellman public value.");
  script_set_attribute(attribute:"description", value:
"The remote SSL/TLS server accepts a weak Diffie-Hellman (DH) public
key value.

This flaw may aid an attacker in conducting a man-in-the-middle (MiTM)
attack against the remote server since it could enable a forced
calculation of a fully predictable Diffie-Hellman secret.

By itself, this flaw is not sufficient to set up a MiTM attack (hence
a risk factor of 'None'), as it would require some SSL implementation
flaws to affect one of the clients connecting to the remote host.");

  script_set_attribute(attribute:"solution", value:
"OpenSSL is affected when compiled in FIPS mode. To resolve this issue,
either upgrade to OpenSSL 1.0.0, disable FIPS mode or configure the
ciphersuite used by the server to not include any Diffie-Hellman key
exchanges.

PolarSSL is affected. To resolve this issue, upgrade to version
0.99-pre3 / 0.14.2 or higher.

If using any other SSL implementation, configure the ciphersuite used
by the server to not include any Diffie-Hellman key exchanges or
contact your vendor for a patch.");
  script_set_attribute(attribute:"see_also", value:"https://www.cl.cam.ac.uk/~rja14/Papers/psandqs.pdf");
  script_set_attribute(attribute:"see_also", value:"https://tls.mbed.org/tech-updates/security-advisories/polarssl-security-advisory-2011-01");
  script_set_attribute(attribute:"risk_factor", value:"None");

  # script_set_attribute(attribute:"vuln_publication_date", value:"2011/02/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/04/11");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"General");

  script_copyright(english:"This script is Copyright (C) 2011-2020 Tenable Network Security, Inc.");



  script_dependencies("ssl_supported_versions.nasl");
  script_require_keys("SSL/Supported");
  exit(0);
}


if (!defined_func("tripledes_cbc_encrypt")) exit(0, "tripledes_cbc_encrypt() not defined.");
if (!defined_func("tripledes_cbc_decrypt")) exit(0, "tripledes_cbc_decrypt() not defined.");

if ( get_kb_item("global_settings/disable_ssl_cipher_neg" ) ) exit(1, "Not negotiating the SSL ciphers, per user config");




include("global_settings.inc");
include("misc_func.inc");
include("byte_func.inc");
include("ssl_funcs.inc");
include("ftp_func.inc");
include("kerberos_func.inc");
include("ldap_func.inc");
include("nntp_func.inc");
include("smtp_func.inc");
include("telnet2_func.inc");
include("dump.inc");


global_var errors, starttls_svcs;

##
#
# Tries to perform a TLS handshake with the Client DH public value set to 1
#
# @param port   - port over which to perform the handshake
# @return       - 1 for success, 0 for failure
#
##
function polarssl_vuln_handshake(port)
{
  local_var soc,version, cipher, pkt, data, hs, rec, msg, crypted, padlen;
  local_var c_random, s_random, master, keyblk, clnt_finished, srv_finished;
  local_var enc_mac_key, dec_mac_key, enc_key, dec_key, enc_iv, dec_iv;
  local_var mac, stored_mac, stored_srv_finished,hello_done, handshake_over;
  local_var parsed, ret, clnt_seq, srv_seq, i, decrypted, encrypted;

  # get a socket to perform a TLS handshake
  soc = open_sock_ssl(port);
  if(! soc) return 0;


  #
  # specifically request TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA,
  # one of the affected cipher suites of the PolarSSL vuln.
  #
  # use only one cipher suite to simplify key, mac, and encryption/decryption
  # operations, as different cipher suites may have a different way to compute keys/mac and
  # encrypt/decrypt data.
  #
  #
  # request oldest affected cipher suite, as older versions
  # of PolarSSL might not support newer suites.
  # this way we can detect older, vulnerable versions of PolarSSL.
  #

  version = TLS_10;
  cipher = ciphers["TLS1_CK_DHE_RSA_WITH_3DES_EDE_CBC_SHA"];

  rec = client_hello(v2hello:FALSE,
                     version: mkbyte((version >>> 8) & 0xff) + mkbyte(version & 0xff),
                     cipherspec:cipher);


  # send ClientHello
  send(socket:soc, data: rec);

  parsed = ssl_parse(blob:rec);
  c_random = mkdword(parsed['time']) + parsed['random'];


  # start collecting handshake messages, which are
  # used to generate the encrypted 'Finished' message
  hs = substr(rec, 5, strlen(rec) -1);

  # read records one at a time
  # expect ServerHello, Certificate, and ServerHelloDone
  #
  hello_done = 0;

  while(! hello_done)
  {
    rec = recv_ssl(socket:soc);
    if(isnull(rec)) break;

    # collect handshake messages
    hs += substr(rec, 5, strlen(rec) -1);


    #
    # ServerHello
    # extract Server.Random for computation of keys
    #
    ret = ssl_find(
        blob:rec,
        "content_type", SSL3_CONTENT_TYPE_HANDSHAKE,
        "handshake_type", SSL3_HANDSHAKE_TYPE_SERVER_HELLO
      );

    if(! isnull(ret))
      s_random = mkdword(ret['time']) + ret['random'];


    # ServerHelloDone
     ret =  ssl_find(
                      blob:rec,
                      "content_type", SSL3_CONTENT_TYPE_HANDSHAKE,
                      "handshake_type", SSL3_HANDSHAKE_TYPE_SERVER_HELLO_DONE
                    );
    if(! isnull(ret)) hello_done = 1;

  }

  if(! hello_done)
  {
    errors += 'Server on port '+port+' did not respond to ClientHello.\n';
    close(soc);
    return 0;
  }

  #
  # create a ClientKeyExchange with DH public value equal to 1
  # this effectively sets the TLS pre master secret to 1, as  1 ^ x mod p = 1
  #
  data = raw_string(0x01);
  msg = tls_mk_handshake_msg(type:SSL3_HANDSHAKE_TYPE_CLIENT_KEY_EXCHANGE,
                             data: mkword(strlen(data)) + data);

  # collect handshake messages
  hs += msg;


  # make it a record
  rec = tls_mk_record(type: SSL3_CONTENT_TYPE_HANDSHAKE, data:msg, version:version);


  #
  # pack multiple records into a single packet
  #
  # this is the first record
  pkt = rec;



  #
  # compute keys
  #
  master = tls_calc_master(premaster:raw_string(0x01), c_random:c_random, s_random:s_random);
  keyblk = tls_derive_keyblk(master:master, c_random:c_random, s_random:s_random);


  #
  # 3DES_SHA1 key material
  #
  # since we have specified TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA
  # the suite uses 20-byte mac keys
  #                24-byte 3des keys
  #                 8-byte iv
  #
  enc_mac_key = substr(keyblk, 0, 19);
  dec_mac_key = substr(keyblk, 20, 39);
  enc_key     = substr(keyblk, 40, 63);
  dec_key     = substr(keyblk, 64, 87);
  enc_iv      = substr(keyblk, 88, 95);
  dec_iv      = substr(keyblk, 96, 103);

  if(COMMAND_LINE)
  {
    dump(ddata:enc_mac_key, dtitle:"enc_mac_key");
    dump(ddata:enc_key, dtitle:"enc_key");
    dump(ddata:enc_iv,  dtitle:"enc_iv");
    dump(ddata:dec_mac_key, dtitle:"dec_mac_key");
    dump(ddata:dec_key, dtitle:"dec_key");
    dump(ddata:dec_iv,  dtitle:"dec_iv");
  }

  #
  # 12-byte client Finished value
  #
  clnt_finished = tls_prf(secret:master, seed:MD5(hs) + SHA1(hs), label:"client finished", nb:12);
  msg = tls_mk_handshake_msg(type:SSL3_HANDSHAKE_TYPE_FINISHED, data: clnt_finished);

  # server has one more handshake message (the client Finished) to include when
  # computing the 12-byte Finished value
  hs += msg;

  # compute 12-byte server Finished value
  srv_finished = tls_prf(secret:master, seed:MD5(hs) + SHA1(hs), label:"server finished", nb:12);
  if(COMMAND_LINE)
    dump(ddata:srv_finished, dtitle:"server finished");

  rec = tls_mk_record(type: SSL3_CONTENT_TYPE_HANDSHAKE, data:msg, version:TLS_10);


  #
  # compute the hmac of the Finished message
  # input: a 64-bit sequence number plus the entire record
  #
  clnt_seq = srv_seq = raw_string(0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00);
  mac = HMAC_SHA1(key:enc_mac_key, data:clnt_seq + rec);

  # attach the mac to the message
  msg += mac;

  #
  # pad to 3DES block size
  #
  padlen = 8 - (strlen(msg) % 8);
  for (i = 0; i < padlen; i++)
    msg += mkbyte(padlen -1);


  # encrypt the client Finished message
  # input: entire msg(including header) + mac + padding
  crypted  = tripledes_cbc_encrypt(data:msg, key: enc_key, iv: enc_iv);
  msg = crypted[0];

  #
  # append ChangeCipherSpec and Finished to the packet
  #
  pkt += tls_mk_record(type:SSL3_CONTENT_TYPE_CHANGECIPHERSPEC, data:raw_string(0x01), version:version);
  pkt += tls_mk_record(type:SSL3_CONTENT_TYPE_HANDSHAKE, data:msg, version:version);

  # send ClientKeyExchange,ChangeCipherSpec and Finished
  send(socket:soc, data:pkt);

  #
  # a vuln server does not check the DH public value, so it will complete the handshake.
  #
  # a patched one will perform the check, and will stop the handshake if the DH public
  # value is out of range. In this case, it will not return ChangeCipherSpec and Finished.
  #
  encrypted = FALSE;
  handshake_over = 0;
  while (! handshake_over)
  {
    rec = recv_ssl(socket:soc);
    if(isnull(rec)) break;

    parsed = ssl_parse(blob:rec, encrypted:encrypted);

    # look for the server Finished message
    if(parsed['content_type']   == SSL3_CONTENT_TYPE_HANDSHAKE)
    {
      # peel off record header
      msg = substr(rec, 5, strlen(rec) -1);
      # decrypt the msg
      decrypted  = tripledes_cbc_decrypt(data:msg, key: dec_key, iv: dec_iv);
      msg = decrypted[0];
      if(COMMAND_LINE)
        dump(ddata:msg, dtitle:"decrypted server Finished");

      # we can also check the pad bytes, too
      # but skipped here

      # extract 12-byte server Finished value
      stored_srv_finished = substr(msg, 4, 15);

      # extract stored mac
      stored_mac = substr(msg, 16, 35);

      # computed mac
      msg = tls_mk_handshake_msg(type:SSL3_HANDSHAKE_TYPE_FINISHED, data: stored_srv_finished);
      rec = tls_mk_record(type:SSL3_CONTENT_TYPE_HANDSHAKE, data:msg, version:version);
      mac = HMAC_SHA1(key:dec_mac_key, data:srv_seq + rec);
      if(COMMAND_LINE)
        dump(ddata:mac, dtitle:"computed mac for server Finished");

      if(mac != stored_mac)
      {
        errors += 'TLS handshake on port '+port+':mac does not match, failed to decrypt server Finished message.\n';
        break;
      }

      if(srv_finished != stored_srv_finished)
      {
        errors += 'TLS handshake on port '+port+':bad server Finished message.\n';
        break;
      }

      # passes all tests, handshake completed!!!
      handshake_over = 1;
    }
    else if (parsed['content_type'] == SSL3_CONTENT_TYPE_CHANGECIPHERSPEC)
    {
      encrypted = TRUE;
    }
  }
  close(soc);

  return handshake_over;
}

# TLS uses network byte order
set_byte_order(BYTE_ORDER_BIG_ENDIAN);

get_kb_item_or_exit("SSL/Supported");

# Get list of ports that use SSL or StartTLS.
ports = get_ssl_ports();
if (isnull(ports) || max_index(ports) == 0)
  exit(1, "The host does not appear to have any SSL-based services.");

# Test every port for the DH vuln
errors = "";
foreach port (ports)
{
  if(polarssl_vuln_handshake(port:port))
    security_note(port:port, extra:'It was possible to complete a full SSL handshake by sending a DH key\nwith a value of 1.');
}
#if (errors) err_print(errors);
