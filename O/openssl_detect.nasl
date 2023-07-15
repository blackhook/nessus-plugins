#TRUSTED 280c8ce5da15e0598a0809c6506227fef3039fb26d026554d476e5b580944463f00036357b0c6190118ef1448d24f0f3ffa71160418a389847757f1aa616821e92674875d7ea2b91e0609e2e13b40cbec99c69e8ae6128c9ea036564250251b72e5ed88ba3b8133fdba4f30447980a56bba04c276e706a6ca13e211436098921d5731d63ff0872501b7bc8ec9e0349537cebd672f8c0217b91b08b24f6d5f7451eafa46126814ad40446689e85a69f84cb4741ff7cdb460c048168d86e0dce8eb44004d96bb4dce87815e7d4f9023b030f5a29dfb50e53f450078895b42c08c17563241bdd9f53f921f98f9ab786b061fb427b51fef6f2e78244060def0c7eeb7e327ec98b0430b987e28600c71c6eedc9f683071e07fd9545f5b1a6e0bb372bad55ad2b546142f5ee90b29ffb1d768c0d5892479c8b59a5316b8580fd6626aa87e753a860e5d4ab9e47c1b43cd8468f1d4be205f09510b20ffc7b496f1364e07911cec7645279e6d446d38f789d445bbea3382c13e8564f47beaa1f208c720ef2bfe213981969cf7b94feb8248c1864088ae91677baf1574251926a9385f64e7839d682487d072da4c49577de5bd8c333eb4e0bc654facf073e791c26419c145aa9675fa1945752bee950de50bcbe52f3c20fae20108ac26827436805ad3dfb4171cd7676cbe1f9adb0d00327ad041b460321375abbeea13babf670a5c5385b
#
# (C) Tenable Network Security, Inc.
#


if ( !defined_func("socket_get_error") ) exit(0);

include("compat.inc");

if (description)
{
 script_id(50845);
 script_version("1.21");
 script_set_attribute(attribute:"plugin_modification_date", value:"2020/06/12");

 script_name(english:"OpenSSL Detection");
 script_summary(english:"OpenSSL detection");

 script_set_attribute(attribute:"synopsis", value:
"The remote service appears to use OpenSSL to encrypt traffic.");

 script_set_attribute(attribute:"description", value:
"Based on its response to a TLS request with a specially crafted
server name extension, it seems that the remote service is using the
OpenSSL library to encrypt traffic.

Note that this plugin can only detect OpenSSL implementations that
have enabled support for TLS extensions (RFC 4366).");
 script_set_attribute(attribute:"solution", value:"n/a");
 script_set_attribute(attribute:"risk_factor", value:"None");
 script_set_attribute(attribute:"see_also", value:"https://www.openssl.org/");
 script_set_attribute(attribute:"plugin_publication_date", value:"2010/11/30");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:openssl:openssl");
 script_set_attribute(attribute:"asset_inventory", value:"True");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2010-2020 and is owned by Tenable, Inc. or an Affiliate thereof.");
 script_family(english:"Service detection");

 script_dependencies("ssl_supported_versions.nasl");
 script_require_keys("SSL/Supported");
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

##
# Formats a server name entry
#
# @param name server name
# @param type server name type
# @return formatted server name
#
##
function server_name(name, type)
{
  return mkbyte(type) + mkword(strlen(name)) + name;
}

##
# Creates a server name extension
#
# @anonparam hostname1, hostname2, ..., hostnamen
# @return formatted server name TLS extension
#
##
function server_name_ext()
{
  local_var host,srvname,srvname_list;

  foreach host (_FCT_ANON_ARGS)
  {
    srvname = server_name(name: host, type:0);
    srvname_list += srvname;
  }

  return    mkword(0) +                         # extension type
            mkword(strlen(srvname_list) + 2) +  # extension length
            mkword(strlen(srvname_list)) +      # length of server name list
            srvname_list;                       # server name list
}

##
# Send ClientHello with server name extension and wait for response
#
# @param soc socket to the ClientHello to
# @param hostname hostname used to generate a TLS server name extension
# @return server response
#
##
function client_hello_sendrecv(soc,hostname)
{
  local_var chello, exts, exts_len, rec, recs,  version;

  version   = raw_string(0x03, 0x01);

  exts = server_name_ext(hostname);
  # length of all extensions
  exts_len  = mkword(strlen(exts));
  chello = client_hello(v2hello:FALSE, version:version,extensions:exts,extensionslen:exts_len);

  send(socket:soc, data: chello);

  # Receive target's response.
  recs = NULL;
  repeat
  {
    rec = recv_ssl(socket:soc);
    if (isnull(rec)) break;
    recs += rec;
  } until (!socket_pending(soc));

  return recs;
}

##
# OpenSSL detection based on response to TLS request with certain TLS server name extensions
#
# @param port SSL port to test
# @param good valid hostname for TLS  server name extension
# @param long hostname with more than 255 bytes
# @param zero hostname with all zero bytes
# @return
#       -  1  test succeeded
#       -  0  test failed
#       -  exit if socket cannot be created on the port
# @remark
# OpenSSL 0.9.8o source code says about servername extension:
#  - Only the hostname type is supported with a maximum length of 255.
#  - The servername is rejected if too long or if it contains zeros,
#    in which case an fatal alert is generated.
#
# RFC 4366 implies that the servername length can be up to 2^16 -1
#
# Starting version 0.9.8f (Release date: Oct 2007), OpenSSL supports TLS extensions,
# but it's disabled by default.
#
# Starting version 0.9.8j (Release date: Jan 2009), the TLS extensions support
# is enabled by default.
#
##
function openssl_tlsext_hostname_test(port, good, long, zero)
{
  local_var soc,soc_err,res, ret;

  # test 1,  valid hostname for openssl tls server name extension
  # expected ret: server hello
  soc = open_sock_ssl(port);
  if ( ! soc ) exit(1,"Failed to open a socket on port "+port+".");
  res = client_hello_sendrecv(soc:soc,hostname:good);
  close(soc);
  if(isnull(res)) return 0;

  # Look for ServerHello
  ret = ssl_find(
    blob:res,
    "content_type", SSL3_CONTENT_TYPE_HANDSHAKE,
    "handshake_type", SSL3_HANDSHAKE_TYPE_SERVER_HELLO
  );
  if(isnull(ret)) return 0;



  # test 2, hostname with more than 255 bytes
  # expected ret for OpenSSL: no response
  #                           the source code says the server should return a fatal alert
  #                           but in several test cases, it responded with a TCP FIN.
  #                           In other test cases, it returns a fatal alert.
  #
  #
  # expected ret for MS TLS implementation (schannel.dll): server hello
  # expected ret for OpenSSL that doesn't support TLS extensions: server hello
  soc = open_sock_ssl(port);
  if ( ! soc ) exit(1, "Failed to open a socket on port "+port+".");
  res = client_hello_sendrecv(soc:soc,hostname:long);
  soc_err = socket_get_error(soc);
  close(soc);

  # Look for unrecognized_name fatal alert
  if(! isnull(res))
  {
    ret = ssl_find(
      blob:res,
      "content_type", SSL3_CONTENT_TYPE_ALERT
    );
    if(isnull(ret) || !(ret['level'] == 2 && ret['description'] == 112)) return 0;
  }
  # Look for TCP FIN/RST
  else
  {
    if(soc_err != ECONNRESET) return 0;
  }

  # test 3, hostname with all zero bytes
  soc = open_sock_ssl(port);
  if ( ! soc ) exit(1, "Failed to open a socket on port "+port+".");
  res = client_hello_sendrecv(soc:soc,hostname:zero);
  soc_err = socket_get_error(soc);
  close(soc);

  # Look for unrecognized_name fatal alert
  if(! isnull(res))
  {
    ret = ssl_find(
      blob:res,
      "content_type", SSL3_CONTENT_TYPE_ALERT
    );
    if(isnull(ret) || !(ret['level'] == 2 && ret['description'] == 112)) return 0;
  }
  # Look for TCP FIN/RST
  else
  {
    if(soc_err != ECONNRESET) return 0;
  }


  # do test1 again to double check
  # expected ret: server hello
  soc = open_sock_ssl(port);
  if ( ! soc ) exit(1,"Failed to open a socket on port "+ port+"." );
  res = client_hello_sendrecv(soc:soc,hostname:good);
  close(soc);
  if(isnull(res)) return 0;
  ret = ssl_find(
    blob:res,
    "content_type", SSL3_CONTENT_TYPE_HANDSHAKE,
    "handshake_type", SSL3_HANDSHAKE_TYPE_SERVER_HELLO
  );
  if(isnull(ret)) return 0;

  # all tests passed
  return 1;

}


get_kb_item_or_exit("SSL/Supported");

port = get_ssl_ports(fork:TRUE);
if (isnull(port))
  exit(1, "The host does not appear to have any SSL-based services.");

# Check for TLS; extensions only available in TLSv1 and later
tls10 = tls11 = tls12 = 0;

list = get_kb_list('SSL/Transport/'+port);
if(! isnull(list))
{
  list = make_list(list);
  foreach encap (list)
  {
    if      (encap == ENCAPS_TLSv1)         tls10 = 1;
    else if (encap == COMPAT_ENCAPS_TLSv11) tls11 = 1;
    else if (encap == COMPAT_ENCAPS_TLSv12) tls12 = 1;
  }
}

if(! (tls10 || tls11 || tls12))
  exit(0, 'The SSL-based service listening on port '+port+' does not appear to support TLSv1 or above.');

# good hostname
good  = 'localhost.localdomain';
# hostname with more than 255 bytes in TLS extension is invalid for OpenSSL
long  = crap(data:good, length:256);
# hostname with all zero bytes in TLS extension is invalid for OpenSSL
zero  = crap(data:raw_string(0x0) ,length:10);

ret = openssl_tlsext_hostname_test(port:port, good:good, long: long, zero: zero);
if(ret == 1)
{
  security_note(port:port);
  set_kb_item(name:"OpenSSL_port", value:port);
}
