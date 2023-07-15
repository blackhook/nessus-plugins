#TRUSTED 6f2f50cc457c930d29b155fd72fd7b30f74bef7e0317b509962e89fa529cb6b10e5bcd05ca7332b81eb61b8529c4f74bf8f620da0ba4513332e09501e8eb3f5880911bd53c89a9b6b914eb10eb40343831946adbba2d2a359e69cb5c7138c51bc3dc08053268aa4aec0c103ef19f6d5b5b026a6f6207e50831c9c64c59016e2289e85181316e371d3a9b744d3c7dea9fee6e4e978404a9dbb5e2d4ea6c3aad31e0cd0dc923b4bc31affc2f4a45aee02f018e2fa22c652675885e35114e22f172bb7cb607e03074c7d9d6c66d007404db5cfa5369268604cbef1c7d7a04363ca98f52e4c7963383d8c44b81927c80e7b31d92ecceedb0b8e66baf7884f9ee3c55209bc307e588da0584ecc5c9623a750692d4bccd85486d8b7f68eb34ae1d1433b7070e14cbfd4fcb5d51a5187632f3c986969766495dd56041d14d8f56a2c151e08b08dd3bee45c67517c5c35389a9c93b0728a8ee5f7ad0eb7734e3c436b8e7b5ee078dd3109ab5d462609fc89f8a20da934d98e200b82010f077f0e751d96a3c71b4b8a252dc3ba9224aafff93683a4c8e2401d5b107b596e44786dfc856d5e176d6a317c26ab696af5da42f5ae5e353e8bf0967974827595831e8576375896062ab8064c719a7f2f66d562f1d95abfc3f66f0c4666b7bbe5b5c2441ef51822c32db1e5bd00b9c4995a77ebb4e2ee2453e9b914e1e6903f1171eaf461793bb
#
# (C) Tenable Network Security, Inc.
#

if (NASL_LEVEL < 3208) exit(0);

include("compat.inc");

if (description)
{
  script_id(61447);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/10/26");

  script_cve_id("CVE-2012-3372");
  script_bugtraq_id(54291);

  script_name(english:"SSL Certificate Signed with the Publicly Known Cyberoam Key");
  script_summary(english:"Checks if the certificate chain is signed by the Cyberoam authority");

  script_set_attribute(attribute:"synopsis", value:
"The SSL certificate for this service was signed by a CA whose private
key is public knowledge.");
  script_set_attribute(attribute:"description", value:
"The X.509 certificate of the remote host was signed by a certificate
belonging to a Certificate Authority (CA) found in Cyberoam devices. 
The private key corresponding to the CA was discovered and publicly
disclosed, meaning that the remote host's X.509 certificate cannot be
trusted.");
  script_set_attribute(attribute:"see_also", value:"https://media.torproject.org/misc/2012-07-03-cyberoam-CVE-2012-3372.txt");
  # https://blog.torproject.org/security-vulnerability-found-cyberoam-dpi-devices-cve-2012-3372
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ebc9c721");
  # http://blog.cyberoam.com/2012/07/cyberoam%E2%80%99s-proactive-steps-in-https-deep-scan-inspection/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?956bd276");
  script_set_attribute(attribute:"see_also", value:"http://blog.cyberoam.com/2012/07/ssl-bridging-cyberoam-approach/");
  script_set_attribute(attribute:"solution", value:"Configure the device to use a device-specific CA certificate.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/06/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/08/07");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:elitecore:cyberoam_unified_threat_management");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"General");

  script_copyright(english:"This script is Copyright (C) 2012-2020 Tenable Network Security, Inc.");

  script_dependencies("ssl_supported_versions.nasl");
  script_require_keys("SSL/Supported");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("x509_func.inc");

get_kb_item_or_exit("SSL/Supported");

# Parse the Cyberoam certificate before forking.
cyberoam = "
MIIFADCCA+igAwIBAgIJAKa1LpKB0iJiMA0GCSqGSIb3DQEBBQUAMIGwMQswCQYD
VQQGEwJJTjEQMA4GA1UECBMHR3VqYXJhdDESMBAGA1UEBxMJQWhtZWRhYmFkMRIw
EAYDVQQKEwlFbGl0ZWNvcmUxJzAlBgNVBAsTHkN5YmVyb2FtIENlcnRpZmljYXRl
IEF1dGhvcml0eTEYMBYGA1UEAxMPQ3liZXJvYW0gU1NMIENBMSQwIgYJKoZIhvcN
AQkBFhVzdXBwb3J0QGVsaXRlY29yZS5jb20wHhcNMTAwNTEwMDc1NjA0WhcNMzYx
MjMxMDc1NjA0WjCBsDELMAkGA1UEBhMCSU4xEDAOBgNVBAgTB0d1amFyYXQxEjAQ
BgNVBAcTCUFobWVkYWJhZDESMBAGA1UEChMJRWxpdGVjb3JlMScwJQYDVQQLEx5D
eWJlcm9hbSBDZXJ0aWZpY2F0ZSBBdXRob3JpdHkxGDAWBgNVBAMTD0N5YmVyb2Ft
IFNTTCBDQTEkMCIGCSqGSIb3DQEJARYVc3VwcG9ydEBlbGl0ZWNvcmUuY29tMIIB
IjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA4ax+WmILhtQDBuW1VAY3gAKo
OBGLD34GyKXHBKepRDLgn7n/3sYuXj4D8Og9sjhdBuw+o+jji2IFtZVbMjas6NU2
BIX8dynmtmTn//d6ACALXEmD6JVP2Wqw+/ZxCQaf+JmPz9zX/6r2y8VpB1b9w1pE
jQTUmAh9yexeWiGX+d0/XvkO+pAFCB8pYUYmU0AiXsU2XqZMj09rMw6tgaQkrQPP
2N/op8qwT+4U35UaexCxjntaSqnoT3ulsTB+adlWcI2VP/+Lg43sW+TIe9EVu09Z
W4BBQ2OjlqSHeVtWfeVwZySrgtyQU7FvDKJeMnGNc/vDlax1+9/zXU7wyyPd5QID
AQABo4IBGTCCARUwHQYDVR0OBBYEFMaO7snsjSZzegkSuHPxvq+3ZYjhMIHlBgNV
HSMEgd0wgdqAFMaO7snsjSZzegkSuHPxvq+3ZYjhoYG2pIGzMIGwMQswCQYDVQQG
EwJJTjEQMA4GA1UECBMHR3VqYXJhdDESMBAGA1UEBxMJQWhtZWRhYmFkMRIwEAYD
VQQKEwlFbGl0ZWNvcmUxJzAlBgNVBAsTHkN5YmVyb2FtIENlcnRpZmljYXRlIEF1
dGhvcml0eTEYMBYGA1UEAxMPQ3liZXJvYW0gU1NMIENBMSQwIgYJKoZIhvcNAQkB
FhVzdXBwb3J0QGVsaXRlY29yZS5jb22CCQCmtS6SgdIiYjAMBgNVHRMEBTADAQH/
MA0GCSqGSIb3DQEBBQUAA4IBAQC3Q8fUg8iAUL2Q01o6GXjThzSI1C95qJK3FAlG
q/XZzhJlJfxHa3rslcDrbNkAdKCnthpF07xYBbAvh0cIn0ST98/2sHJDJ4sg3Pqp
HUtNOL3PpNMgdqXtoQgKcm8XtkBOppGrCR4HTcRjf0ZLfWP71S3/Ne1o1U10KrPh
LWGYME+4Uh6lo7OBdZp8C8IjPYT2GSCquh/wWrtSYspfO4HJw/5dXaY7wfTh8P0k
/ENLBUUzENiiDiyhXKEZvCAbX+KWNq2T4w7r+411ycV828cuwZx/MehWQrw2SpjC
3sVdb7GwxgxcyGE6TM39Ht3Jl4scTFmKZrG8A9BwTYQsvm6I";

cyberoam = str_replace(string:cyberoam, find:'\n', replace:"");
cyberoam = base64_decode(str:cyberoam);
cyberoam = parse_der_cert(cert:cyberoam);
cyberoam = cyberoam["tbsCertificate"];

if (isnull(cyberoam))
  exit(1, "Failed to parse builtin certificate.");

# Get list of ports that use SSL or StartTLS.
port = get_ssl_ports(fork:TRUE);
if (isnull(port))
  exit(1, "The host does not appear to have any SSL-based services.");

# Get the certificate chain from the target.
chain = get_server_cert(
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
# certificate in the chain was issued by the offending certificate,
# and that its public key matches to avoid other certs with the same
# Distinguished Name.
#
# We know from screenshots of affected SSL connections that the device
# includes its CA certificate as part of the chain.
top = chain[max_index(chain) - 1];
top = top["tbsCertificate"];

if (
  !is_signed_by(top, cyberoam) ||
  !obj_cmp(top["subjectPublicKeyInfo"], cyberoam["subjectPublicKeyInfo"])
) exit(0, "The certificate chain from port " + port + " is not affected.");

# Report our findings.
report = NULL;
if (report_verbosity > 0)
{
  cert = chain[0];
  cert = cert["tbsCertificate"];

  report =
    '\nThe following certificate has been issued by a certificate' +
    '\nauthority whose private key is public knowledge :' +
    '\n' +
    '\n  Subject : ' + format_dn(cert["subject"]) +
    '\n  Issuer  : ' + format_dn(cert["issuer"]) +
    '\n';
}

security_warning(port:port, extra:report);
