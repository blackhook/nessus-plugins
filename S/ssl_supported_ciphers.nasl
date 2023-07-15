#TRUSTED 827ead59d97f92a11fa6030320d08f214542014b96bb6dcfcd86424056f76798017f89ed0ad43a9e7021a85457b4d6471a5e93a3bdefa252f7c25b0c253714e1ee485266a91480ec393708884b3de22423d8008241011eb265046eae971c97965d6dd97ec49e2396d7bb99a5f1887b5437521a0581db624bd48493ebebf9b575143a79982c6ca19356241e992be7ef18626445cbd86342cd4e4a584c36d0dfe6735ee4cb84693d6ac3b4176e3792337e959f1c6b5d9123895ed8a2f300baf3da61d1a75a8cf920cb2c3b1e1a1fb9b20de3672215d82c61d8a02513c545c6fbc9bccf0283aba9313dc86ea799b1f695bd98a72a4ff5054463f4f870dc4f5871694ba14631af2c17164dc7091a7fd34705566ec446a0c4b169e0530ea0ae47a59a58d8229d5ee017e2f86e3008498620870e65ec65b1f56b32b29096e44d0b21644adec70e1f617fa925db4c3768e5ceff0e8f5d4601185a36a62ee78b2cf697a35c13233f02b69dc61603713cb1baa0b99e8764ce38814f82737a3092ee7cbd7836fcbe6938f0c24d32c68e22bf76df5d9af50adacbe16ce531f47fc504ee402ca174fe5a43b03fcefb476e00f4c781d94642439a238f4c315df7311b7da9f14174ef55e81c0e00b6a52aa34c68f7976a51ef7c029490b21915130a7d2dc663b837516cb7d0f561a5d5f12e2eb5bca4e71b480480a884ef28eb9ea5438e137772
#TRUST-RSA-SHA256 47d4c2c400fa8847bf5ab7018de5eeaf7c0a3c232ca018e187ca662b8e77deab61a74cd17d026414989310cd702c53148edb99f569855ae23c4dfc67a1db87115510f21b937c342dc22addcdde7e09353db3f76cbc1570e8c0ed906737e64b24808e6988690a101e0b81a16ead89baff319437bb0400203167fc50db243f520ab4d5efd76967dd43ac237442a0477b9032c99080e9498f4c02db9063e2e4ad5d089c4e05c9c5167e36c996f11dd9aa880f19e762f63bf968360250cad81f50da56ac0d5c4bd6e5841bc25cbf3f07bcd1de26afe58fe0f54779438a23b226f7d9368564874fbd5584437c3b3b04e435700fee0836d7c74b2cc027960cf2bc2de4eac3fd10b5cb1c6b345392180747b2acadcfa58c36355be8c7ba275445684a0246bdc9c416ff9aac9e5b60690cd0ac162c7f24855b45be177edc0d23a618293bd4051bf40ddd01244829a593e0bf6e152c5a370d918af36dcfc59f4743b835c6e5bfa70fd9f9b0dde30f0a39927be3ec1eae3414a41e2a4353858d4ab9678531c528c6a93564a1da1a3440ed71eaef2319c7b4bce5a322ebe58077d7d2dfa42274028e5c65f41cabaf6a2563083dc8e314a92bc934af49c81d6ada975ef86f4163cd85a71937fc32483a1c002b0a061bee4aa472987157e7444e312f075dd23491c0e56f25ecec889a916199945732e035ec92859f83ce8da5dd4a36410039b8
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(21643);
  script_version("1.84");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/07/10");

  script_name(english:"SSL Cipher Suites Supported");
  script_summary(english:"Checks which SSL cipher suites are supported.");

  script_set_attribute(attribute:"synopsis", value:
"The remote service encrypts communications using SSL.");
  script_set_attribute(attribute:"description", value:
"This plugin detects which SSL ciphers are supported by the remote
service for encrypting communications.");
  script_set_attribute(attribute:"see_also", value:"https://www.openssl.org/docs/man1.0.2/man1/ciphers.html");
  # https://web.archive.org/web/20171007050702/https://wiki.openssl.org/index.php/Manual:Ciphers(1)
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e17ffced");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2006/06/05");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"General");

  script_copyright(english:"This script is Copyright (C) 2006-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssl_supported_versions.nasl", "find_service_dtls.nasl");
  script_require_ports("SSL/Supported", "DTLS/Supported");

  script_timeout(30 * 60);

  exit(0);
}

include('byte_func.inc');
include('ftp_func.inc');
include('kerberos_func.inc');
include('ldap_func.inc');
include('nntp_func.inc');
include('smtp_func.inc');
include('ssl_funcs.inc');
include('telnet2_func.inc');
include('rsync.inc');


##
# We want to format the cipher report returned from cipher_report()
# We are simply removing the SSL version in each strength section
# @remark The param 'report' is assumed to be already formatted by 'cipher_report()'
# @param report A report from 'cipher_report()'
# @return A modified report
##
function format_cipher_report(report)
{
  local_var regex, version;

  regex = make_list("(\s)+(SSLv2)\s", "(\s)+(SSLv3)\s", "(\s)+(TLSv1)\s",
                    "(\s)+(TLSv11)\s", "(\s)+(TLSv12)\s");

  foreach version (regex)
      report = ereg_replace(pattern:version, replace:'\n', string:report);

  return report;
}


##
# Identifies the cipher or ciphers supported by an SSL server as
# entries in a list of possible cipher suites.
#
# @param <rec:array>     Supported cipher information returned by server.
# @param <ciphers:array> Array of possible SSL/TLS cipher suites.
#
# @return A list of supported ciphers as keys in the 'ciphers' array.
##
function get_received_ciphers(rec, ciphers)
{
  local_var str, srv_cipher;

  result = make_list();

  # Old protocols return a list of ciphers, which can either be
  # a subset of the ones we sent (we only send one), or a subset
  # of the ciphers it supports. We'll be conservative and store
  # all ciphers returned.
  foreach srv_cipher (rec["cipher_specs"])
  {
    if (encaps == ENCAPS_SSLv2)
    {
      str = raw_string(
        (srv_cipher >> 16) & 0xFF,
        (srv_cipher >>  8) & 0xFF,
        (srv_cipher >>  0) & 0xFF
      );
    }
    else
    {
      str = raw_string(
        (srv_cipher >>  8) & 0xFF,
        (srv_cipher >>  0) & 0xFF
      );
    }

    foreach var known_cipher (keys(ciphers))
    {
      if (str == ciphers[known_cipher] && !isnull(ciphers[known_cipher]))
        result = make_list(result, known_cipher);
    }
  }

  return result;
}

##
# Make the ciphers array for a ClientHello message based on an array
# of cipher suites.
#
# @param <cipher_set:array> The array of ciphers to encode
# @param <encaps:string>    The protocol being tested
# @return A raw string to use with ClientHello
##
function create_client_hello_ciphers(cipher_set, encaps)
{
  var client_hello_bytes;
  var cipher;

  foreach cipher (sort(keys(cipher_set)))
  {
    if (!isnull(cipher_set[cipher]))
      client_hello_bytes += cipher_set[cipher];
  }

  return client_hello_bytes;
}

##
# Determine whether or not to add an ECC extension to the ClientHello message
#
# @param <cipher_set:array> The array of ciphers to encode in the ClientHello
# @param <encaps:string>    The protocol being tested
# @return TRUE if an extension should be added, FALSE otherwise
##
function is_ec_extension_required(cipher_set, encaps)
{
  var cipher;

  # We can only include extensions if this is TLSv1 or greater
  if (encaps >= ENCAPS_TLSv1)
  {
    foreach cipher (sort(keys(cipher_set)))
    {
      # Some SSL implementations require a supported named curve for it
      # to return a ServerHello, so we will send EC extensions, claiming
      # to support all curves and EC point formats.
      if(!isnull(cipher_set[cipher]) && tls_is_ec_cipher(cipher))
        return TRUE;
    }
  }

  return FALSE;
}


##
# Send a ClientHello offering a set of supported SSL/TLS cipher suites.
# Accept the ServerHello response which should contain at least one agreed
# upon cipher if the server supports one of the offered suites.
#
# @param  <cipher_to_check:array> The array of cipher suites offered to the server.
# @param  <encaps:int>            The protocol being tested.
# @param  <port:int>              The port the server is listening on.
# @param  <known_ciphers:int>     A count of the cipher suites discovered so far.
# @param  <dtls:bool>             Is this a DTLS UDP port?
#
# @return An array of information about the cipher suite selected by the server.
##
function test_for_ssl_support(ciphers_to_check, encaps, port, known_ciphers, dtls)
{
  # When we fail to open a socket, we'll pause for a few seconds and
  # try again. We'll only do this so many times before we consider the
  # service too slow, however.
  var at_least_one_successful_connection = FALSE;
  var secure_renegotiation = FALSE;
  var exts = "";
  var soc;
  var ssl_ver;
  var fn = "test_for_ssl_support() - ";

  if(isnull(dtls))
    dtls = FALSE;

  if(isnull(known_ciphers))
    known_ciphers = 0;

  if(isnull(ciphers_to_check) || isnull(encaps) || isnull(port))
    return NULL;

  if(dtls)
  {
    if(encaps == COMPAT_ENCAPS_TLSv11)
      ssl_ver = raw_string(0xfe, 0xff);
    else if(encaps == COMPAT_ENCAPS_TLSv12)
      ssl_ver = raw_string(0xfe, 0xfd);
    else
    {
      ssl_dbg(src:fn,msg: "Attempt to use DTLS with an unsupported encapsulation (" + encaps + ") on port " + port + ".");
      return NULL;
    }
  }
  else
  {
    if (encaps == ENCAPS_SSLv2)      ssl_ver = raw_string(0x00, 0x02);
    else if (encaps == ENCAPS_SSLv3) ssl_ver = raw_string(0x03, 0x00);
    else if (encaps == ENCAPS_TLSv1) ssl_ver = raw_string(0x03, 0x01);
    else if (encaps == COMPAT_ENCAPS_TLSv11) ssl_ver = raw_string(0x03, 0x02);
    else if (encaps == COMPAT_ENCAPS_TLSv12) ssl_ver = raw_string(0x03, 0x03);
    # note TLS 1.3 is handled separately below
  }

  if(is_ec_extension_required(cipher_set:ciphers_to_check, encaps:encaps))
    exts = tls_ext_ec() + tls_ext_ec_pt_fmt();

  if (encaps >= ENCAPS_TLSv1)
  {
    # Include an SNI extension if it makes sense to
    var host = get_host_name();
    if (host != get_host_ip() && host != NULL)
       exts += tls_ext_sni(hostname:host);

    if (encaps == COMPAT_ENCAPS_TLSv12)
      exts += tls_ext_sig_algs();
  }

  if (encaps >= ENCAPS_SSLv3)
  {
    secure_renegotiation = TRUE;
  }

  if (exts == "")
    exts = NULL;

  var cipher_message = create_client_hello_ciphers(cipher_set:ciphers_to_check, encaps:encaps);
  var rec, recs;

  var test_mode = FALSE;

  if(dtls)
  {
    if (get_kb_item("TEST_dtls_in_flatline"))
      test_mode = TRUE;

    recs = get_dtls_server_response(port:port, encaps:encaps, cipherspec:cipher_message,
                                    exts:exts, test_mode:test_mode,
                                    securerenegotiation:secure_renegotiation);
  }
  else
  {
    if (get_kb_item("TEST_ssl_supported_ciphers_do_not_open_socket"))
      test_mode = TRUE;
    else
    {
      var pauses_taken = 0;

      # Connect to the port, issuing the StartTLS command if necessary.
      while (!(soc = open_sock_ssl(port)))
      {
        pauses_taken++;
        if (pauses_taken > 5)
        {
          if (at_least_one_successful_connection)
            set_kb_item(name:"scan_interference/ssl_supported_ciphers", value:port);
          ssl_dbg(src:fn,msg:"Failed to connect to port " + port + " too "+
            "many times, exiting.");
          exit(1, "Failed to connect to " + port + " too many times.");
        }
        else
        {
          ssl_dbg(src:fn,msg:"Failed to connect to port " + port + ", " +
            "pausing before retrying.");
          replace_kb_item(name:"ssl_supported_ciphers/pauses_taken/" + port, value:pauses_taken);
          sleep(pauses_taken * 2);
        }
      }
    }

    at_least_one_successful_connection = TRUE;

    # Connect to the port, issuing the StartTLS command if necessary.
    recs = get_tls_server_response(soc:soc, port:port, encaps:encaps, cipherspec:cipher_message,
                                            exts:exts, test_mode:test_mode,
                                            securerenegotiation:secure_renegotiation);

    if (!isnull(recs) && encaps == COMPAT_ENCAPS_TLSv13)
      ssl_ver = raw_string(3,3);

    if(soc && !test_mode)
      close(soc);
  }

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
  }

  if (isnull(rec))
  {
    ssl_dbg(src:fn, msg:"No records received.");
  }
  # Ensure that the SSL version is what we expect.
  else if (rec["version"] != getword(blob:ssl_ver, pos:0))
  {
    ssl_dbg(src:fn, msg:"record version (" + rec["version"] + ") doesn't match " + ssl_ver);
    rec = NULL;
  }
  else if (isnull(rec['cipher_specs']) && !isnull(rec['cipher_spec']))
  {
    rec['cipher_specs'] = make_list(rec['cipher_spec']);
  }

  return rec;
}

##
# Remove the cipher_report() footer. We only need one
# cipher_list_size will determine how many times we remove the footer.
# @remark The param 'report' is assumed to be already formatted by 'cipher_report()'
# @param report A report from 'cipher_report()'
# @param cipher_array_size Length of supported_ciphers array.
# @return A modified report
##
function remove_footer(report, cipher_array_size)
{
  local_var footer, tmp;

  # If the size is only 1 then we do not want to remove the footer
  if (cipher_array_size == 1 ) return report;

  footer ='
The fields above are :

  {Tenable ciphername}
  {Cipher ID code}
  Kex={key exchange}
  Auth={authentication}
  Encrypt={symmetric encryption method}
  MAC={message authentication code}
  {export flag}';

  # Remove the footer except for one hence the '-1'
  tmp = str_replace(string:report, find:footer, replace:'', count:cipher_array_size-1);

  return tmp;
}

if ( get_kb_item("global_settings/disable_ssl_cipher_neg" ) )
  exit(1, "Not negotiating the SSL ciphers, per user config.");

if(!get_kb_item("SSL/Supported") && !get_kb_item("DTLS/Supported"))
  exit(1, "Neither the 'SSL/Supported' nor the 'DTLS/Supported' flag is set.");

set_byte_order(BYTE_ORDER_BIG_ENDIAN);

# Get a port to operate on, forking for each one.
is_dtls = FALSE;
pp_info = get_tls_dtls_ports(fork:TRUE, dtls:TRUE, check_port:TRUE);
port = pp_info["port"];
if (isnull(port))
  exit(1, "The host does not appear to have any TLS or DTLS based services.");

# If it's encapsulated already, make sure it's a type we support.
if(pp_info["proto"] == "tls")
{
  is_dtls = FALSE;
  encaps = get_kb_item("Transports/TCP/" + port);
}
else if(pp_info["proto"] == "dtls")
{
  is_dtls = TRUE;
  encaps = get_kb_item("Transports/UDP/" + port);
}
else
  exit(1, "A bad protocol was returned from get_tls_dtls_ports(). (" + pp_info["port"] + "/" + pp_info["proto"] + ")");

if (encaps > ENCAPS_IP && (encaps < ENCAPS_SSLv2 || encaps > COMPAT_ENCAPS_TLSv13))
  exit(1, pp_info["l4_proto"] + " port " + port + " uses an unsupported encapsulation method.");

# For debugging
fn = "ssl_supported_ciphers.nasl";

# Determine whether this port uses StartTLS.
starttls = get_kb_list("*/" + port + "/starttls");
starttls = (!isnull(starttls) && max_index(keys(starttls)));

ssl_dbg(src:fn,msg:"Testing port "+port+". starttls:"+starttls);

# Choose which transports to test.
if (thorough_tests)
{
  supported = make_list(
    COMPAT_ENCAPS_TLSv13,
    COMPAT_ENCAPS_TLSv12,
    COMPAT_ENCAPS_TLSv11,
    ENCAPS_TLSv1,
    ENCAPS_SSLv3,
    ENCAPS_SSLv2
  );
}
else
{
  if(is_dtls)
    supported = get_kb_list_or_exit("DTLS/Transport/" + port);
  else
    supported = get_kb_list_or_exit("SSL/Transport/" + port);
}

# Determine which ciphers are supported.
supported_ciphers = make_array();
known_ciphers = 0;

#Try all at once eliminating the cipher suite chosen by the server
#until all of the server's cipher suites have been enumerated.
foreach encaps (supported)
{
  ssl_dbg(src:fn,msg:"Testing encaps " + ENCAPS_NAMES[encaps] +
    " on port " + port + ".");

  start_supported_ciphers_size = max_index(keys(supported_ciphers));

  all_ciphers = get_valid_ciphers_for_encaps(encaps:encaps, ciphers:ciphers);

  first_time = TRUE;
  added_at_least_one = NULL;
  ciphers_to_check = all_ciphers;

  # Iterate over each cipher.
  while(first_time || added_at_least_one)
  {
    added_at_least_one = FALSE;

    recs = test_for_ssl_support(ciphers_to_check:ciphers_to_check,
                                encaps:encaps, port:port,
                                known_ciphers:known_ciphers, dtls:is_dtls);
    first_time = FALSE;
    if(isnull(recs))
      continue;

    result = get_received_ciphers(rec:recs, ciphers:ciphers_to_check);
    foreach known_cipher (result)
    {
      ciphers_to_check[known_cipher] = NULL;
      known_ciphers++;
      added_at_least_one = TRUE;
      supported_ciphers[encaps][known_cipher] = TRUE;

      ssl_dbg(src:fn,msg:"Found supported cipher: " + known_cipher + " via " +
        ENCAPS_NAMES[encaps]+" on " + pp_info["l4_proto"] + " port " + port + ".");
    }
  }

  if (max_index(keys(supported_ciphers)) == start_supported_ciphers_size)
  {
    #iterate one by one
    ssl_dbg(src:fn,msg:"The first offer of all ciphers returned " +
      "nothing.  Trying each cipher, one at a time " +
      ENCAPS_NAMES[encaps] + " on " + pp_info["l4_proto"] + " port " + port + ".");

    #We already know that this is SSL and at least one cipher suite is supported, if we get a
    #NULL response on the first try, move over to the legacy strategy.
    foreach cipher(keys(all_ciphers))
    {
      ciphers_to_check = {};
      ciphers_to_check[cipher] = ciphers[cipher];

      recs = test_for_ssl_support(ciphers_to_check:ciphers_to_check,
                                  encaps:encaps, port:port, dtls:is_dtls);
      if(isnull(recs))
        continue;

      result = get_received_ciphers(rec:recs, ciphers:ciphers_to_check);
      foreach known_cipher (result)
      {
        ciphers_to_check[known_cipher] = NULL;
        known_ciphers++;
        supported_ciphers[encaps][known_cipher] = TRUE;

        ssl_dbg(src:fn,msg:"Found supported cipher: " + known_cipher + " via " +
          ENCAPS_NAMES[encaps] + " on " + pp_info["l4_proto"] + " port " + port + ".");
      }
    }
  }
}

supported_ciphers_size = max_index(keys(supported_ciphers));

if (supported_ciphers_size == 0)
  exit(0, pp_info["l4_proto"] + " port " + port + " does not appear to have any ciphers enabled.");

# Stash the list of supported ciphers in the KB for future use.
# Each cipher is match to the corresponding version
# Generate report for each version and its ciphers
foreach var encap (sort(supported))
{
  if (isnull(supported_ciphers[encap])) continue;
  supported_ciphers_per_encap = keys(supported_ciphers[encap]);

  foreach cipher (supported_ciphers_per_encap)
  {
    if(is_dtls)
      set_kb_item(name:"DTLS/Ciphers/" + port, value:cipher);
    else
      set_kb_item(name:"SSL/Ciphers/" + port, value:cipher);
  }

  if(is_dtls)
  {
    if(encaps == COMPAT_ENCAPS_TLSv11)
      ssl_version = "DTLSv10";
    else if(encaps == COMPAT_ENCAPS_TLSv12)
      ssl_version = "DTLSv12";
  }
  else
  {
    if (encap == ENCAPS_SSLv2)      ssl_version = "SSLv2";
    else if (encap == ENCAPS_SSLv3) ssl_version = "SSLv3";
    else if (encap == ENCAPS_TLSv1) ssl_version = "TLSv1";
    else if (encap == COMPAT_ENCAPS_TLSv11) ssl_version = "TLSv11";
    else if (encap == COMPAT_ENCAPS_TLSv12) ssl_version = "TLSv12";
    else if (encap == COMPAT_ENCAPS_TLSv13) ssl_version = "TLSv13";
  }

  version_header = '\nSSL Version : ' + ssl_version;

  raw_report = cipher_report(supported_ciphers_per_encap);
  report = version_header + format_cipher_report(report:raw_report) + report;
}

report = remove_footer(report:report, cipher_array_size:supported_ciphers_size);

# Finish generating the report of supported /iphers.
if (isnull(report))
  exit(1, "cipher_report() returned NULL for port " + port + ".");

report =
  '\nHere is the list of SSL ciphers supported by the remote server :' +
  '\nEach group is reported per SSL Version.' +
  '\n' + report;

if (starttls)
{
  report +=
    '\nNote that this service does not encrypt traffic by default but does' +
    '\nsupport upgrading to an encrypted connection using STARTTLS.' +
    '\n';
}

security_note(port:port, proto:tolower(pp_info["l4_proto"]), extra:report);

