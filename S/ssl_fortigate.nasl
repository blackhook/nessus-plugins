#TRUSTED 5706920aba4a57994d52522577c8674521fc162c4d00b2e6cd228a1e816a3152f406a5b25274ed17b98644bf938413aacb6bbf5bbb35f8b2f74a77145abaa1c9178bb927eb7f4c6911a31c7a15a0968eb287c795fead23e2ea070d0f5ffec35304d522b380db34f28d9ef76b3e90c53fad3a07eb7fda3461ebf7aa6ed5117e14d57df9dd70ccb19dd87592bc0789c0a1da61636d9863630e9bb987f9c2d2fc981038fdfa3cc07c51a115941af55d0944eaba48e945c90d35fb00a6c2f31ac12ab5778566213f45c10467a57ea46c6a0415a592fe9aed326377f570f14e95e107ced2ced8bfcd394f4470560e0e093a36e9612103660dda4505ee874c4aeccec40371a0b698cf11840840fb94504fd8450d757a8d0f81a75b6d0e42f2d6987632d85f1b1d98bd7f5e63a7b16030c98a2b8cbbd2131f7d98fd9ee5e1414e5c2d8d840a7cbaa5a55f5047f56a0643e6774151742633f0366cdc42f752e78878529e7153e23c892a9d51054b93438a6fd9f6aeb634dd9390349b3fe303ce82627c33d050868bbbde71969eefc617f47252c8ef734b734a69e6f212b4a48371a27e0b7c0532040131020ec82aac2afa4b15c9da20ac0bb582b2cbdb479e07e07cbc4ea8a90329e6ff20dda4272d9158286d919220aa06db12cdf836755d33707614a24d3a08579338ef094e35728d069f792602917fbb97a779fb1aac9a7cb3c85ff7
#
# (C) Tenable Network Security, Inc.
#

if (NASL_LEVEL < 3208) exit(0);

include("compat.inc");

if (description)
{
  script_id(62969);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/02/11");

  script_cve_id("CVE-2012-4948");
  script_bugtraq_id(56382);
  script_xref(name:"CERT", value:"111708");

  script_name(english:"SSL Certificate Signed with the Compromised FortiGate Key");
  script_summary(english:"Checks if the certificate chain is signed by the FortiGate authority");

  script_set_attribute(attribute:"synopsis", value:
"The SSL certificate for this service was signed by a certificate
authority (CA) whose private key has been compromised.");
  script_set_attribute(attribute:"description", value:
"The X.509 certificate of the remote host was signed by a certificate
belonging to a Certificate Authority (CA) found in FortiGate devices.
The private key corresponding to the CA has been compromised, meaning
that the remote host's X.509 certificate cannot be trusted.

Certificate chains descending from this CA could allow an attacker to
perform man-in-the-middle attacks and decode traffic.");
  script_set_attribute(attribute:"solution", value:
"Configure the device to use a device-specific CA certificate.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:H/Au:N/C:C/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:H/PR:N/UI:R/S:U/C:H/I:L/A:N");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2012-4948");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/10/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/11/19");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/h:fortinet:fortigate");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"General");

  script_copyright(english:"This script is Copyright (C) 2012-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssl_supported_versions.nasl");
  script_require_keys("Settings/ParanoidReport", "SSL/Supported");

  exit(0);
}

include("x509_func.inc");

get_kb_item_or_exit("SSL/Supported");

# We only have the DN of the cert, which can easily collide with another
# certificate causing a false positive.
if (report_paranoia < 2)
  audit(AUDIT_PARANOID);

# All the information we have is the DN of the FortiGate CA, which
# we'll create in the same format that we'll see it in a parsed cert.
var fortigate =  make_nested_list(
  make_list(
    '2.5.4.6',
    'US'
  ),
  make_list(
    '2.5.4.8',
    'California'
  ),
  make_list(
    '2.5.4.7',
    'Sunnyvale'
  ),
  make_list(
    '2.5.4.10',
    'Fortinet'
  ),
  make_list(
    '2.5.4.11',
    'Certificate Authority'
  ),
  make_list(
    '2.5.4.3',
    'FortiGate CA'
  ),
  make_list(
    '1.2.840.113549.1.9.1',
    'support@fortinet.com'
  )
);

# Get list of ports that use SSL or StartTLS.
var port = get_ssl_ports(fork:TRUE);
if (isnull(port))
  exit(1, "The host does not appear to have any SSL-based services.");

# Get the certificate chain from the target.
var chain = get_server_cert(
  port     : port,
  encoding : "der",
  getchain : TRUE
);
if (isnull(chain) || max_index(chain) <= 0)
  exit(1, "Failed to retrieve the certificate chain from port " + port + ".");

chain = parse_cert_chain(chain);
if (isnull(chain))
  exit(1, "Failed to parse certificate chain on port " + port + ".");

# The offending certificate is self-signed, meaning that it can only
# occur at the top of the certificate chain. Check that the top
# certificate in the chain was issued by a certificate with a
# Distinguished Name that matches the FortiGate CA.
#
# We don't know if the FortiGate device includes its own certificate
# in the chain when it man-in-the-middles a connection, so we can't
# look for the FortiGate CA's public key (even if we knew it). This
# means that false positives are possible if there is a
# device-specific CA created with the same Distinguished Name.
var top = chain[max_index(chain) - 1];
top = top["tbsCertificate"];

if (!obj_cmp(top["issuer"], fortigate))
  exit(0, "The certificate chain from port " + port + " is not affected.");

# Report our findings.
var report = NULL;
if (report_verbosity > 0)
{
  var cert = chain[0];
  cert = cert["tbsCertificate"];

  report =
    '\nThe following certificate has been issued by a certificate' +
    '\nauthority whose private key has been compromised :' +
    '\n' +
    '\n  Subject : ' + format_dn(cert["subject"]) +
    '\n  Issuer  : ' + format_dn(cert["issuer"]) +
    '\n';
}

security_report_v4(port:port, extra:report, severity:SECURITY_WARNING);
