#TRUSTED 5f1cb1315b3950ef0014ba36deab1698dada12a6e8bb28e3b56eb5573ce5a562ca9116a9084a202749d6a016145e5883c300f4b839b2dc4d6c2a57d2ebeb48b3bd3b053f9dffae7ff733b637f07ca5040e26b31d39c5a27166a94b226662aa6eef61583ed1e36f774213de9ca986b63d6909ca9381a5b1cc57529967d8ead16b81419dbe6390a33756b9acb0e03fa64b46a257289fd0dde667dbc8f00271208b453d8e2c373dc9bf53bcda499df142257f478bebec40461f3915fed55ce4d9ebf74f02a8ffe2f93e5f572153ce1f2699f5a1b1e69680ffd49ed3c9f638d5148778e8d13450e7c4d34bf1943062bd84534993abb18efa461e7264f7c5ed0d8edd24b2f2bd51f3fc774b6d31e665ca20396cae0629c106aaf24b4f6d15230544486a37df30c2a4eba1e4820073d7077b98323aff7265da749abde3679965eaedd7c9115a801e7c889be10df671ef716750979214aa83eb7f29ec74842fc3e7e30c68caaa0bd43c57a56077a36dff7c270407e14e0780c1f5596685f67af0b44a42bfa3d62c981613a992d3a1963ffbfb54f60276ff7a6016493d0ec7f35eabf05df27c7eef4a6cae6eb2a09496d70f11e31096afaf0be9c05e392947b4959a86925c304d5ae0177f5947ffb1c811a6e6f2eb3e7309b7ab235062c086b9ec5b329af9b025a9d19af7c9095a853602ddb338c1ea7e2a632b0fa47cbafe1539d638e3
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(103864);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/10/26");

  script_cve_id("CVE-2017-15361");
  script_xref(name:"IAVA", value:"2017-A-0313");

  script_name(english:"SSL Certificate Contains Weak RSA Key (Infineon TPM / ROCA)");
  script_summary(english:"Checks that the certificate chain has no weak RSA keys");

  script_set_attribute(attribute:"synopsis", value:
"The X.509 certificate chain used by this service contains certificates
with RSA keys that may have been improperly generated.");
  script_set_attribute(attribute:"description", value:
"At least one of the X.509 certificates sent by the remote host has an RSA key
that appears to be generated improperly, most likely by a TPM (Trusted Platform
Module) produced by Infineon Technologies.
A third party may be able to recover the private key from the certificate's
public key. This may allow an attacker to impersonate an HTTPS website or
decrypt SSL/TLS sessions to the remote service.");
  script_set_attribute(attribute:"see_also", value:"https://crocs.fi.muni.cz/public/papers/rsa_ccs17");
  # https://www.infineon.com/cms/en/product/promopages/rsa-update/?redirId=59206
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?9357cd2f");
  # https://sites.google.com/a/chromium.org/dev/chromium-os/tpm_firmware_update
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?3495f5d8");
  script_set_attribute(attribute:"see_also", value:"https://support.hp.com/us-en/document/c05792935");
  script_set_attribute(attribute:"see_also", value:"https://support.lenovo.com/us/en/product_security/len-15552");
  # https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/ADV170012
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?5b614caf");
  script_set_attribute(attribute:"solution", value:
"Upgrade the firmware for all Infineon TPMs and revoke the affected
certificates, including any certificates signed by an affected key.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-15361");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_publication_date", value:"2017/10/17");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"General");

  script_copyright(english:"This script is Copyright (C) 2017-2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssl_certificate_chain.nasl");

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("ssl_funcs.inc");
include("x509_func.inc");
include("byte_func.inc");

PRINTS = [
  '6',
  '1e',
  '7e',
  '402',
  '161a',
  '1a316',
  '30af2',
  '7ffffe',
  '1ffffffe',
  '7ffffffe',
  '4000402',
  '1fffffffffe',
  '7fffffffffe',
  '7ffffffffffe',
  '12dd703303aed2',
  '7fffffffffffffe',
  '1434026619900b0a',
  '7fffffffffffffffe',
  '1164729716b1d977e',
  '147811a48004962078a',
  'b4010404000640502',
  '7fffffffffffffffffffe',
  '1fffffffffffffffffffffe',
  '1000000006000001800000002',
  '1ffffffffffffffffffffffffe',
  '16380e9115bd964257768fe396',
  '27816ea9821633397be6a897e1a',
  '1752639f4e85b003685cbe7192ba',
  '1fffffffffffffffffffffffffffe',
  '6ca09850c2813205a04c81430a190536',
  '7fffffffffffffffffffffffffffffffe',
  '1fffffffffffffffffffffffffffffffffe',
  '7fffffffffffffffffffffffffffffffffe',
  '1ffffffffffffffffffffffffffffffffffffe',
  '50c018bc00482458dac35b1a2412003d18030a',
  '161fb414d76af63826461899071bd5baca0b7e1a',
  '7fffffffffffffffffffffffffffffffffffffffe',
  '7ffffffffffffffffffffffffffffffffffffffffe'
];
# Decode these as bigints just once
for (i = 0; i < max_index(PRINTS); ++i)
  PRINTS[i] = bn_hex2raw(PRINTS[i]);

# This is parallel to the PRINTS list, above... first element here is
# used with first element of PRINTS, etc.
PRIMES = [
  3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67,
  71, 73, 79, 83, 89, 97, 101, 103, 107, 109, 113, 127, 131, 137, 139,
  149, 151, 157, 163, 167
];

function roca_check_modulus(n)
{
  local_var i, finger, bitmask;

  # Borrows the detection method from https://github.com/crocs-muni/roca
  # Try all primes and their fingerprints
  for (i = 0; i < max_index(PRINTS); ++i)
  {
    finger = bn_lshift_one(count:int(bn_raw2dec(bn_mod(n, bn_dec2raw(PRIMES[i])))));
    # Check if any of the bits in the fingerprint are present
    bitmask = bn_and(a:finger, b:PRINTS[i]);
    if (bn_cmp(key1:bitmask, key2:bn_dec2raw("0")) == 0)
      return FALSE;
  }

  return TRUE;
}

# Shifts the number `1` left by up to a few hundred bits, such as `1 << 64`,
# returning a bignum. Basically implements 1 * 2**y, but is faster than
# doing an exponent.
# OpenSSL recommending using BN_lshift, but NASL doesn't have this.
function bn_lshift_one(count)
{
  local_var bytes;

  bytes = crap(data:'\x00', length:(count / 8) + 1);
  # Set the single bit that we care about
  bytes[0] = raw_string(1 << (count % 8));

  return bytes;
}

# Performs bitwise-AND of two bignums. They do not have to be the
# same length
function bn_and(a, b)
{
  local_var a_len, b_len, max, ret;

  a_len = strlen(a);
  b_len = strlen(b);
  if (a_len > b_len)
    max = a_len;
  else
    max = b_len;

  # Pad out whichever is shorter than the other
  if (a_len < max)
    a = crap(data:'\x00', length:max - a_len) + a;
  if (b_len < max)
    b = crap(data:'\x00', length:max - b_len) + b;

  # Do the ANDing
  ret = crap(data:'\x00', length:max);
  for (i = 0; i < max; ++i)
    ret[i] = mkbyte(ord(a[i]) & ord(b[i]));

  return ret;
}

###
# Main part of the script
###

port = get_ssl_ports(fork:TRUE);
if (isnull(port))
  exit(0, "No SSL services were detected");

# Gather up the certs from SNI and non-SNI connections

certs = [];

sni_certs = get_server_cert(port:port, getchain:TRUE, encoding:"der", sni:TRUE);
if (!isnull(sni_certs))
  certs = make_list(certs, sni_certs);

other_certs = get_server_cert(port:port, getchain:TRUE, encoding:"der", sni:FALSE);
if (!isnull(other_certs))
  certs = make_list(certs, other_certs);

certs = list_uniq(certs);

results = "";
unparsed = 0;
nonrsa = 0;
foreach cert (certs)
{
  parsed = parse_der_cert(cert:cert);
  # If we couldn't parse the certificate or if it's not an RSA public key
  if (isnull(parsed))
  {
    unparsed++;
    continue;
  }

  if (empty_or_null(parsed.tbsCertificate.subjectPublicKeyInfo) || "RSA" >!< oid_name[parsed.tbsCertificate.subjectPublicKeyInfo[0]])
  {
    nonrsa++;
    continue;
  }

  if (!empty_or_null(parsed.tbsCertificate.subjectPublicKeyInfo[1]) && roca_check_modulus(n:parsed.tbsCertificate.subjectPublicKeyInfo[1][0]))
    results += " - Subject: " + format_dn(parsed.tbsCertificate.subject) + '\n';
}

if (results != "")
{
  security_report_v4(
    port:port,
    severity:SECURITY_WARNING,
    extra:'The following certificates appear to be affected :\n' + results
  );
}
else
{
  exit(0, "None of the " + max_index(certs) + " certificates on port " + port + " appear to have an affected public key (unparsable: " + unparsed + ", non-RSA: " + nonrsa + ").");
}
