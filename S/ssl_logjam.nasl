#TRUSTED 7362fb99ebfe3a78b3a2474a997de61bb57f5ca07c48c3cca316ac15e0cddac6fd3aea60c1e5aea27df6177e233529e7a6bc04befbef7f0a01fa6da18c9312a13366ad0772558a680fa88a044d5a55e609b4bf949a23dd3d4536a3a64a106fad662239bc06c1d4ba142704e00419652c6c5123f111b1cc8f7f890b1d55bb3825f0c5d3612df3a65279e18444a92bf5c2a9a900fcd8b7147a21ade2cb6cbf58d97d360e098d09788037d9e967487478e50f4f7ea631d5c4db9bb97d17ff1f6449754719de7531f4ab778d4c96ea939050e8b72bcd01cf781e661a222778a897d4a9014ccfb54e1f79cb1a7b184f69a565380cd3670326da1782a8ae4213a29009b50cc16c4534f3e3759cd15f4fd45b1257cb1f5fc34c887eb699c18b3289b8a76b299d7c8c531f28783ebcae3924fa8c1897466dc69bca9b9541db00d9674742e15e4e02db66690643e9e5662474573112aa11e6c4748ee80351a05d91e22a230afb7797ee0337a1e2863baf72371af190ca115f5a17b9a24f1f2e50b3966e566631a4f7452dafc2a32721f5008127497ab39d32b2d08cc997285e883165b3387b547067179b6f0d9fcfb4db00f00f9c94f08b6b599146ea277002369be5c205df7e842361d1e4761e9f7512f2b9e249ad64244ad76a0769d02e92fe520f087bdbf075955a0acb80f395d7eeae1ea56f003d9b9e497f0a78685c56c0b32e409d
#TRUST-RSA-SHA256 68b88d435efb9b64649670f483bf7a28f1e831e39fa83cf8c6528c600e133eb3a6364a9e47f7631a0f7ad412c2c5dc00e138a15f1ad6d3cc179b50c8afc6b7de4048964b271b51c63d2a6c2d851c5419d470718403d5a39a42dc2339325ddb13d023fb83253b692cbec1703794f63cac7beebba106e9bd2843dc95085b7fc6214fec1a1fb3cc7e428ec658c6f67233129b1a7379bde9038dfcaf95cc979cc423e52cb016b9cc74189fa01509be3c9fe77b0f89002ef7f18ea8ff1bff8515f5c57b9bfd2d6c17591116344fb4c542177a0a5eb53cee35ffe0deb7c9718b71185df159159f29f4adb3f749958a10a4fb50c510255a134bf0e30b9b75b8ddda9abae7dbe88627ee0be19bb20f72ffcf5ccbe4c5586c3ea3643f42a11c771107e12c3da062d243af0f591a72c13160eaeec44ccf20f47ec67d845405566fe09d4ff2e1b4b3787402c766eecb44ed8f2fc27bd15d35270b27f1533f46b4c70ec1044fc3a9d14f8f64e737f0a03ef8cae952e8f781e4c22087e935e7fe00d5fbd7b2c06253f363c7654d539e46d02051010361daa6a31dca2071969c61c829af753e41448ec465a3b3da5df7ee04bc84caf7b60f26d154ca7a5dd8bae17149a7467b5ce467a063c2db09d73d45491de2ad921ff35d579a17311f1465150ee619247b172eff3fc0709a095050edb4a6a19d3b7e0c6f369d8356ba3d777fa4ad908110bd
#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(83875);
  script_version("1.40");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/05");

  script_cve_id("CVE-2015-4000");
  script_bugtraq_id(74733);
  script_xref(name:"CEA-ID", value:"CEA-2021-0004");

  script_name(english:"SSL/TLS Diffie-Hellman Modulus <= 1024 Bits (Logjam)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host allows SSL/TLS connections with one or more
Diffie-Hellman moduli less than or equal to 1024 bits.");
  script_set_attribute(attribute:"description", value:
"The remote host allows SSL/TLS connections with one or more
Diffie-Hellman moduli less than or equal to 1024 bits. Through
cryptanalysis, a third party may be able to find the shared secret in
a short amount of time (depending on modulus size and attacker
resources). This may allow an attacker to recover the plaintext or
potentially violate the integrity of connections.");
  script_set_attribute(attribute:"see_also", value:"https://weakdh.org/");
  script_set_attribute(attribute:"solution", value:
"Reconfigure the service to use a unique Diffie-Hellman moduli of 2048
bits or greater.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"manual");
  script_set_attribute(attribute:"cvss_score_rationale", value:"An in depth analysis by Tenable researchers revealed the Access Complexity to be high.");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"in_the_news", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/05/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/05/28");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:openssl:openssl");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2015-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssl_supported_ciphers.nasl");
  script_require_ports("SSL/Supported", "DTLS/Supported");

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
include('debug.inc');

if ( get_kb_item('global_settings/disable_ssl_cipher_neg' ) ) exit(1, 'Not negotiating the SSL ciphers per user config.');

if(!get_kb_item('SSL/Supported') && !get_kb_item('DTLS/Supported'))
  exit(1, "Neither the 'SSL/Supported' nor the 'DTLS/Supported' flag is set.");

var oakley_grp1_modp = raw_string( # 768 bits
  0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
  0xC9, 0x0F, 0xDA, 0xA2, 0x21, 0x68, 0xC2, 0x34,
  0xC4, 0xC6, 0x62, 0x8B, 0x80, 0xDC, 0x1C, 0xD1,
  0x29, 0x02, 0x4E, 0x08, 0x8A, 0x67, 0xCC, 0x74,
  0x02, 0x0B, 0xBE, 0xA6, 0x3B, 0x13, 0x9B, 0x22,
  0x51, 0x4A, 0x08, 0x79, 0x8E, 0x34, 0x04, 0xDD,
  0xEF, 0x95, 0x19, 0xB3, 0xCD, 0x3A, 0x43, 0x1B,
  0x30, 0x2B, 0x0A, 0x6D, 0xF2, 0x5F, 0x14, 0x37,
  0x4F, 0xE1, 0x35, 0x6D, 0x6D, 0x51, 0xC2, 0x45,
  0xE4, 0x85, 0xB5, 0x76, 0x62, 0x5E, 0x7E, 0xC6,
  0xF4, 0x4C, 0x42, 0xE9, 0xA6, 0x3A, 0x36, 0x20,
  0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
);

var oakley_grp2_modp = raw_string( # 1024 bits
  0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
  0xC9, 0x0F, 0xDA, 0xA2, 0x21, 0x68, 0xC2, 0x34,
  0xC4, 0xC6, 0x62, 0x8B, 0x80, 0xDC, 0x1C, 0xD1,
  0x29, 0x02, 0x4E, 0x08, 0x8A, 0x67, 0xCC, 0x74,
  0x02, 0x0B, 0xBE, 0xA6, 0x3B, 0x13, 0x9B, 0x22,
  0x51, 0x4A, 0x08, 0x79, 0x8E, 0x34, 0x04, 0xDD,
  0xEF, 0x95, 0x19, 0xB3, 0xCD, 0x3A, 0x43, 0x1B,
  0x30, 0x2B, 0x0A, 0x6D, 0xF2, 0x5F, 0x14, 0x37,
  0x4F, 0xE1, 0x35, 0x6D, 0x6D, 0x51, 0xC2, 0x45,
  0xE4, 0x85, 0xB5, 0x76, 0x62, 0x5E, 0x7E, 0xC6,
  0xF4, 0x4C, 0x42, 0xE9, 0xA6, 0x37, 0xED, 0x6B,
  0x0B, 0xFF, 0x5C, 0xB6, 0xF4, 0x06, 0xB7, 0xED,
  0xEE, 0x38, 0x6B, 0xFB, 0x5A, 0x89, 0x9F, 0xA5,
  0xAE, 0x9F, 0x24, 0x11, 0x7C, 0x4B, 0x1F, 0xE6,
  0x49, 0x28, 0x66, 0x51, 0xEC, 0xE6, 0x53, 0x81,
  0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
);

var encaps_lookup = make_array(
  ENCAPS_SSLv2,  'SSLv2',
  ENCAPS_SSLv23, 'SSLv23',
  ENCAPS_SSLv3,  'SSLv3',
  ENCAPS_TLSv1,  'TLSv1.0',
  COMPAT_ENCAPS_TLSv11, 'TLSv1.1',
  COMPAT_ENCAPS_TLSv12, 'TLSv1.2'
);

set_byte_order(BYTE_ORDER_BIG_ENDIAN);

# Get a port to operate on, forking for each one.
var pp_info = get_tls_dtls_ports(fork:TRUE, dtls:TRUE, check_port:TRUE, ciphers:TRUE);
var port = pp_info['port'];
if (isnull(port))
  exit(1, 'The host does not appear to have any TLS or DTLS based services.');

var supported;
if(pp_info['proto'] == 'tls')
  supported = get_kb_list_or_exit('SSL/Transport/' + port);
else if(pp_info['proto'] == 'dtls')
  supported = get_kb_list_or_exit('DTLS/Transport/' + port);
else
  exit(1, 'A bad protocol was returned from get_tls_dtls_ports(). (' + pp_info['port'] + '/' + pp_info['proto'] + ')');

var cipher_suites = pp_info['ciphers'];
if(isnull(cipher_suites))
  exit(0, 'No ciphers were found for ' + pp_info['l4_proto'] + ' port ' + port + '.');
cipher_suites = make_list(cipher_suites);

# declare all vars used in foreach loops below
var report, encaps, ssl_ver, v2, cipher, recs, skex, possible_audit, fn, mod_bit_len, dh_mod, known_mod;

report = '';

foreach encaps (supported)
{
  ssl_ver = NULL;
  v2 = NULL;

  if (encaps == ENCAPS_SSLv2)
    ssl_ver = raw_string(0x00, 0x02);
  else if (encaps == ENCAPS_SSLv3 || encaps == ENCAPS_SSLv23)
    ssl_ver = raw_string(0x03, 0x00);
  else if (encaps == ENCAPS_TLSv1)
    ssl_ver = raw_string(0x03, 0x01);
  else if (encaps == COMPAT_ENCAPS_TLSv11)
    ssl_ver = raw_string(0x03, 0x02);
  else if (encaps == COMPAT_ENCAPS_TLSv12)
    ssl_ver = raw_string(0x03, 0x03);

  v2 = (encaps == ENCAPS_SSLv2);


  foreach cipher (cipher_suites)
  {
    if(pp_info['proto'] == 'tls')
    {
      recs = get_tls_server_response(port:port, encaps:encaps, cipherspec:ciphers[cipher]);
      fn = 'get_tls_server_response';
    }
    else if(pp_info['proto'] == 'dtls')
    {
      recs = get_dtls_server_response(port:port, encaps:encaps, cipherspec:ciphers[cipher]);
      fn = 'get_dtls_server_response';
    }

    if(strlen(recs) == 0)
    {
      dbg::log(src:fn, msg: cipher + ' on port ' + port +
                                    ' : ClientHello handshake was empty or null. Possibly timed (10 seconds)');
      continue;
    }
    else if(strlen(recs) > 0)
    {
      dbg::log(src:fn, msg: cipher + 'ClientHello handshake on port ' + port + '\n' + obj_rep(recs));
    }

    # Server Key Exchange
    skex = ssl_find(
      blob:recs,
      'content_type', SSL3_CONTENT_TYPE_HANDSHAKE,
      'handshake_type', SSL3_HANDSHAKE_TYPE_SERVER_KEY_EXCHANGE
    );

    # Server Key Exchange, additional debugging
    if (!empty_or_null(skex))
    {
      fn = 'ssl_find';
      dbg::log(src:fn, msg:cipher + ' on port ' + port + ' :\n\t' + obj_rep(skex));
    }

    possible_audit = '';

    if (!isnull(skex) && strlen(skex['data']) >= 2)
    {
      skex = ssl_parse_srv_kex(blob:skex['data'], cipher:ciphers_desc[cipher], version: ssl_ver);

      # After parsing the server kex, dump additional debugging info
      if (!empty_or_null(skex))
      {
        fn = 'ssl_parse_srv_kex';
        dbg::log(src:fn, msg:'Parsing Server KEX data for ' + cipher + ' on port ' + port +
                              ' :\n\tGenerator (dh_g) = ' + obj_rep(skex['dh_g']) +
                              '\n\tPrime Modulus (dh_p) = ' + obj_rep(skex['dh_p']) +
                              '\n\tPublic Value (dh_y) = ' + obj_rep(skex['dh_y']) +
                              '\n\tKEX (kex) = ' + skex['kex'] +
                              '\n\tSignature (sig) = ' + obj_rep(skex['sig']));
      }

      if(skex['kex'] == 'dh')
      {
        dbg::log(src:SCRIPT_NAME, msg:'Diffie-Hellman server KEX received for ' + cipher + ' on port ' + port +
                                      ' :\n\tProtocol: ' + ENCAPS_NAMES[encaps] +
                                      '\n\tCipher: ' + ciphers_desc[cipher] +
                                      '\n\tPrime modulus length: ' + serialize(strlen(skex['dh_p'])));

        if(empty_or_null(skex['dh_p']))
        {
          if(isnull(skex['dh_p']))
            dbg::log(src:SCRIPT_NAME, msg:'For ' + cipher + ' on port ' + port + ', Prime Modulus is NULL!');

          possible_audit = 'Invalid prime modulus received from server.';
          continue;
        }

        mod_bit_len = strlen(skex['dh_p']) * 8;
        dh_mod = skex['dh_p'];

        known_mod = (dh_mod == oakley_grp1_modp || dh_mod == oakley_grp2_modp);

        # Used by pci_weak_dh_under_2048.nasl
        if (get_kb_item('Settings/PCI_DSS'))
        {
          set_kb_item(name:'PCI/weak_dh_ssl', value:port);
          replace_kb_item(name:'PCI/weak_dh_ssl/modlen/' + port, value:mod_bit_len);
        }

        if((mod_bit_len <= 1024 && mod_bit_len >= 768 && ((report_paranoia == 2) || known_mod)) ||
            mod_bit_len < 768)
        {
          report +=
          '\n  SSL/TLS version  : ' + encaps_lookup[encaps] +
          '\n  Cipher suite     : ' + cipher +
          '\n  Diffie-Hellman MODP size (bits) : ' + mod_bit_len;

          if(dh_mod == oakley_grp1_modp)
             report +=
             '\n    Warning - This is a known static Oakley Group1 modulus. This may make' +
             '\n    the remote host more vulnerable to the Logjam attack.';
          if(dh_mod == oakley_grp2_modp)
             report +=
             '\n    Warning - This is a known static Oakley Group2 modulus. This may make' +
             '\n    the remote host more vulnerable to the Logjam attack.';

          if(mod_bit_len > 768)
            report += '\n  Logjam attack difficulty : Hard (would require nation-state resources)';
          else if(mod_bit_len > 512 && mod_bit_len <= 768)
            report += '\n  Logjam attack difficulty : Medium (would require university resources)';
          else
            report += '\n  Logjam attack difficulty : Easy (could be carried out by individuals)';
          report += '\n';
        }
      }
    }
  }
}

if(report)
{
  report = '\nVulnerable connection combinations :\n' + report;
  # temporarily adding report to debugging - remove later
  dbg::log(src:SCRIPT_NAME, msg:'Scan Report : \n\t' + report);
  security_report_v4(port:port, proto:pp_info['l4_proto'], extra:report, severity:SECURITY_NOTE);
}
else if(strlen(possible_audit) > 0)
{
  exit(0, possible_audit);
}
else audit(AUDIT_HOST_NOT, 'affected');
