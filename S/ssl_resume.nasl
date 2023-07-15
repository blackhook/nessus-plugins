#TRUSTED 264264365a164ef3312b71cf0aef2f6b6289b97fc5f1f3b375fcf91930a17f8a878c3494490ce2d8aaa46354aadd965db78c3e6be1dc9c81cd29bc1f67b51a7634bdc5df869a19c2fbe32850ea569ae8c6e3eb12135179e6c70797a70174f9f21b204d549a9cea3949ba09bd168919a2de9a146b4cdecfa212da89fb27c0ddd2090db3c6b4aa0d2cd3cb2a1566d11dfce475b885c890b3e37b93149882c14e472eb42a6715a6132a825fb12f033af4b16738346e30c91a3e9e3cd235959fdefde8d440e2e0b3d8f64592e05d7f97195956b524fb097a03cf80a243593eababdb99f599516b92fef79dda794c278c9e704b6137aa86522b83f27a17a0a7443551cddd9dceb6b4ea8e791298d9a0ee515ed77e8ea75b35d65f9e28c8e4fbb94480bf9c3c1bdbd083fe627b0b87a1472e8ca1d0744bf79a7f7f85b3128dde970d2022e807aa08b44dd279c1ceb8ca273dc5cc5f0a14a40445b4215ae7b6ecec42fc38560eea4cccf0d0a728441944c60dcfa9707dc8f47683f7651b16d1fdbf0770803b9cf3b13f414086a1c2c131876676097088d24bc7c94d21f770e078c35db3786ac4c434c090e180bedd159428b337533d00a74cc9f53ee3672f380e2319570f50db537c6218d3b13ec80191e9f37c0aac3f9b7e7bc86e5429713f78c75842cc3d1f8330e0996ba68fd8d4588a8d735aa42a04ed2bd593d7394319607d7397
#
# (C) Tenable Network Security, Inc.
#

if (!defined_func("socketpair")) exit(0, "socketpair() not defined.");
if ( NASL_LEVEL < 4000 ) exit(0);

include("compat.inc");

if (description)
{
  script_id(51891);
  script_version("1.23");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/09/13");

  script_name(english:"SSL Session Resume Supported");
  script_summary(english:"Checks if caching and resuming SSL sessions is supported.");

  script_set_attribute(attribute:"synopsis", value:"The remote host allows resuming SSL sessions.");
  script_set_attribute(attribute:"description", value:
"This script detects whether a host allows resuming SSL sessions by
performing a full SSL handshake to receive a session ID, and then
reconnecting with the previously used session ID.  If the server
accepts the session ID in the second connection, the server maintains
a cache of sessions that can be resumed.");

  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/02/07");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"General");

  script_copyright(english:"This script is Copyright (C) 2011-2021 Tenable Network Security, Inc.");

  script_dependencies("ssl_supported_ciphers.nasl");
  script_require_keys("SSL/Supported");

  exit(0);
}

include("byte_func.inc");
include("ftp_func.inc");
include("global_settings.inc");
include("kerberos_func.inc");
include("ldap_func.inc");
include("nntp_func.inc");
include("misc_func.inc");
include("smtp_func.inc");
include("ssl_funcs.inc");
include("telnet2_func.inc");

global_var comps, disabled, enabled, port;

function initial(encaps)
{
  local_var comp, rec, recs, sock;

  # Create initial session using OpenSSL library.
  sock = open_sock_ssl(port);
  if (!sock)
    return NULL;
  recs = ssl3_handshake(socket:sock, transport:encaps);
  close(sock);

  # Find the ClientHello record.
  rec = ssl_find(
    blob:recs,
    "content_type", SSL3_CONTENT_TYPE_HANDSHAKE,
    "handshake_type", SSL3_HANDSHAKE_TYPE_CLIENT_HELLO
  );
  if (isnull(rec))
    return NULL;

  # Cache the list of compression methods for use in the resume
  # ClientHello. We do this because we've observed oddly behaving
  # servers.
  comps = "";
  foreach comp (rec["compression_methods"])
  {
    comps += mkbyte(comp);
  }

  # Find the ServerHello record.
  rec = ssl_find(
    blob:recs,
    "content_type", SSL3_CONTENT_TYPE_HANDSHAKE,
    "handshake_type", SSL3_HANDSHAKE_TYPE_SERVER_HELLO
  );
  if (isnull(rec))
    return NULL;

  # Check if the port gave us a session ID.
  if (rec["session_id"] == "")
    return NULL;

  return rec;
}

function resume(cipher, session)
{
  local_var rec, recs, sock;

  # Convert cipher name to its ID.
  if (typeof(cipher) == "int")
    cipher = mkword(cipher);
  else
    cipher = ciphers[cipher];

  # Manually craft a ClientHello with the specified cipher and a
  # session ID given to us previously.
  rec = client_hello(
    version    : mkword(session["version"]),
    sessionid  : session["session_id"],
    cipherspec : cipher,
    compmeths  : comps,
    v2hello    : FALSE
  );
  if (isnull(rec))
    return NULL;

  # Request to resume a previous session.
  sock = open_sock_ssl(port);
  if (!sock)
    return NULL;
  send(socket:sock, data:rec);

  # Receive the target's response.
  recs = "";
  repeat
  {
    rec = recv_ssl(socket:sock);
    if (isnull(rec))
      break;
    recs += rec;
  } until (!socket_pending(sock));
  close(sock);
  if (recs == "")
    return NULL;

  # Find the ServerHello record.
  rec = ssl_find(
    blob:recs,
    "content_type", SSL3_CONTENT_TYPE_HANDSHAKE,
    "handshake_type", SSL3_HANDSHAKE_TYPE_SERVER_HELLO
  );
  if (isnull(rec))
    return NULL;

  # Check that the server didn't switch the version.
  if (rec["version"] != session["version"])
    return NULL;

  # Check that we have resumed the session.
  if (rec["session_id"] != session["session_id"])
    return FALSE;

  # Check that the server didn't switch the cipher.
  if (mkword(rec["cipher_spec"]) != cipher)
    return FALSE;

  return TRUE;
}

function resume_different(ciphers, re, session)
{
  local_var cipher, res;

  foreach cipher (ciphers)
  {
    # Skip ciphers that aren't for this protocol.
    if (!isnull(re) && cipher !~ re)
      continue;

	# Skip over the cipher that was negotiated during the initial
    # connection.
    if (getword(blob:ciphers[cipher], pos:0) == session["cipher_spec"])
      continue;

    res = resume(cipher:cipher, session:session);

    # Check for errors beyond the server rejecting our resume attempt.
    if (isnull(res))
      return NULL;

    if (res)
      return cipher;
  }

  return NULL;
}

function remember(cipher, encaps, session, type)
{
  local_var id, old;

  if (!port || !encaps)
    return;

  id = hexstr(session["session_id"]);
  old = cipher_name(id:session["cipher_spec"], encaps:encaps);

  set_kb_item(name:"SSL/Resume/" + type, value:port);
  set_kb_item(name:"SSL/Resume/" + type + "/" + port, value:encaps);

  if ( !isnull(id) ) set_kb_item(name:"SSL/Resume/" + type + "/" + port + "/" + encaps + "/Session_ID", value:id);
  if ( !isnull(old) ) set_kb_item(name:"SSL/Resume/" + type + "/" + port + "/" + encaps + "/Initial", value:old);
  if ( !isnull(cipher) ) set_kb_item(name:"SSL/Resume/" + type + "/" + port + "/" + encaps + "/Resumed", value:cipher);
}

function check(encaps, re)
{
  local_var cipher, ciphers_ge, ciphers_lt, different, init_strength;
  local_var session, strength;

  # Check if we can resume with the same cipher.
  session = initial(encaps:encaps);
  if (isnull(session))
    return FALSE;

  if (!resume(cipher:session["cipher_spec"], session:session))
    return FALSE;

  if (port) set_kb_item(name:"SSL/Resume", value:port);
  if (encaps) set_kb_item(name:"SSL/Resume/" + port, value:encaps);

  # Keep track of whether we've successfully resumed with a different cipher,
  # to save us a connection attempt.
  different = FALSE;

  # Check if we can resume with a different disabled cipher.
  session = initial(encaps:encaps);
  if (isnull(session))
    return TRUE;

  cipher = resume_different(ciphers:disabled, session:session, re:re);
  if (!isnull(cipher))
  {
    remember(cipher:cipher, encaps:encaps, session:session, type:"Disabled");
    different = TRUE;
  }

  # Get the strength of the cipher that the server selected.
  init_strength = cipher_strength(session["cipher_spec"], encaps:encaps);

  # We have no good way to force the use of a specific cipher when we
  # use OpenSSL to connect. We don't trust CIPHER_STRENGTH_MAX ciphers
  # to necessarily be that strong, it's an assumption, so we won't
  # perform cipher strength comparisons in that case.
  if (isnull(init_strength) || init_strength == CIPHER_STRENGTH_MAX)
    return TRUE;

  # Create two lists of ciphers: one consisting of ciphers weaker than
  # the one negotiated during the initial connection, and the other
  # not.
  ciphers_lt = make_list();
  ciphers_ge = make_list();
  foreach cipher (enabled)
  {
    # Skip ciphers that aren't for this protocol.
    if (cipher !~ re)
      continue;

    # Skip over the cipher that was negotiated during the initial
    # connection.
    if (getword(blob:ciphers[cipher], pos:0) == session["cipher_spec"])
      continue;

    # Get the strength of this cipher, but skip if it's untrustworthy.
    strength = cipher_strength(cipher, encaps:encaps);
    if (isnull(strength) || strength == CIPHER_STRENGTH_MAX)
      continue;

    if (strength < init_strength)
      ciphers_lt = make_list(ciphers_lt, cipher);
    else
      ciphers_ge = make_list(ciphers_ge, cipher);
  }

  # Check if we can resume with different enabled cipher of lesser strength.
  session = initial(encaps:encaps);
  if (isnull(session))
    return TRUE;

  cipher = resume_different(ciphers:ciphers_lt, session:session);
  if (!isnull(cipher))
  {
    remember(cipher:cipher, encaps:encaps, session:session, type:"Weaker");
    different = TRUE;
  }

  # Check if we can resume with a different enabled cipher of greater or equal
  # strength, but only if we haven't already successfully resumed with a
  # different cipher.
  if (!different)
  {
    session = initial(encaps:encaps);
    if (isnull(session))
      return TRUE;

    cipher = resume_different(ciphers:ciphers_ge, session:session);
    different = (!isnull(cipher));
  }

  if (different)
    remember(cipher:cipher, encaps:encaps, session:session, type:"Different");

  return TRUE;
}

get_kb_item_or_exit("SSL/Supported");

# Get a port to operate on, forking for each one.
port = get_ssl_ports(fork:TRUE);
if (isnull(port))
  exit(1, "The host does not appear to have any SSL-based services.");

# Find out if the port is open.
if (!get_port_state(port))
  exit(0, "Port " + port + " is not open.");

# All parameters in SSL are big-endian.
set_byte_order(BYTE_ORDER_BIG_ENDIAN);

# Decide which encapsulation methods to test.
if (thorough_tests)
{
  supported = make_list(
    ENCAPS_SSLv2,
    ENCAPS_SSLv3,
    ENCAPS_TLSv1,
    COMPAT_ENCAPS_TLSv11,
    COMPAT_ENCAPS_TLSv12
  );
}
else
{
  supported = get_kb_list_or_exit("SSL/Transport/" + port);
}

# Get the list of ciphers enabled on this port.
enabled = get_kb_list_or_exit("SSL/Ciphers/" + port);
enabled = make_list(enabled);
if (max_index(enabled) == 0)
  exit(1, "No supported ciphers were found for port " + port + ".");

# Derive the list of ciphers disabled on this port.
disabled = make_list();
foreach cipher (keys(ciphers))
{
  foreach var enabled_cipher (enabled)
  {
    if (cipher == enabled_cipher)
    {
      cipher = NULL;
      break;
    }
  }

  if (cipher)
    disabled = make_list(disabled, cipher);
}

# Check for resume capability in each transport.
resumes = make_list();
foreach var encaps (supported)
{
  if (encaps == ENCAPS_SSLv2)
  {
    # Resuming an SSLv2 session requires seeing inside of the final,
    # encrypted record in the handshake process. We can't do this
    # without our own SSLv2 protocol library.
    continue;
  }
  else if (encaps == ENCAPS_SSLv3 && check(encaps:encaps, re:"^SSL3_"))
  {
    resumes = make_list(resumes, "SSLv3");
  }
  else if (encaps >= ENCAPS_TLSv1 && encaps <= COMPAT_ENCAPS_TLSv12 && check(encaps:encaps, re:"^TLS1_"))
  {
    # For the moment, we can't detect TLSv1 resume support in every
    # case. Since we use OpenSSL for the initial connection, it
    # sends its default list of ciphers. If the fake cipher that
    # indicates secure session resume support is in that cipher
    # list, which depends on the version of OpenSSL, and the server
    # supports it, we won't be able to detect resume support.
    resumes = make_list(resumes, "TLSv1");
  }
}

if (max_index(resumes) == 0)
  exit(0, "This port does not support resuming SSL / TLS sessions.");

# Report our findings.
resumes = join(resumes, sep:" / ");
report = '\nThis port supports resuming ' + resumes + ' sessions.\n';
security_note(port:port, extra:report);
