#TRUSTED 79fcc03979550585466acd1efe06a04795ce352425e67af7e2e631a7d92fa58dfc4083f2212baf950daf72195cb2eea09cf2472b44863fc1344e8227fd81e1a61a3ccfc0b5179ae755601f1706c7dd8e5ac59873133f555208e24ae7824e7ce67739c68822096321e7a7952e46f5f259477bbb2f37cfd90e4cd354fa02e06f03a9fa851e4104d5a6bfabfb0711353859c2d82c5f02efaf5c8718d55df3978277abba386ced5a037c70abe69debefdaec6edff435f4b6a84a5c11f632bfe249bc0b8ec78c2b7428a488acc163c1107719a4860f8b2bcda26bac47de7b05d58f1f3bf9971d896515c2731be893e0ec15745cda56897eddd9fc9fb563fd8866668a80e034f259d85d0ae9949386649634dae6c128a9401d178119aaa5673691182624e934ba6c0793f5ba8d585e1aba531838e3dd91b3d9275e6d73b6c7cd107571b96c0fde2ba69fab433329e139c5a95683ad90e2bdb35cee1cc4a0a8705b548279060b7e1142d270bf7472ed5598cae5ccc08891e9d01498c6bac7a0c1b1a719b8e73c90c42fb09b83b3592952605d6207fa4ff0f2d329af502efec855e3e477df73fecdd1b7512da6d3b5c9229f74601f888da8b8c8b61fe7f2aa51a8f59c001ccc77a803410518f7c2465f4e08f37ad7e68517d1a345a93c87302284a536a0797672ca2c958b0b0f1335fff75102fa22a06fcdb19955419e2a7d749edb3e40
#
# (C) Tenable Network Security, Inc.
#

if (NASL_LEVEL < 3208) exit(0);

include("compat.inc");

if (description)
{
  script_id(63398);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/10/26");

  script_name(english:"SSL Certificate Chain Contains Illegitimate TURKTRUST Intermediate CA");
  script_summary(english:"Checks if the certificate chain contains an illegitimate intermediate CA");

  script_set_attribute(attribute:"synopsis", value:
"The SSL certificate chain for this service is not to be trusted.");
  script_set_attribute(attribute:"description", value:
"The X.509 certificate chain sent by the remote host either contains or
is signed by an intermediate Certificate Authority (CA) that was
accidentally issued by TURKTRUST. 

Certificate chains descending from this intermediate CA could allow an
attacker to perform man-in-the-middle attacks and decode traffic.");
  script_set_attribute(attribute:"solution", value:
"Ensure that your software or operating system blacklists the
intermediate CAs.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:N");
  script_set_attribute(attribute:"see_also", value:"https://docs.microsoft.com/en-us/security-updates/SecurityAdvisories/2013/2798897");
  # https://security.googleblog.com/2013/01/enhancing-digital-certificate-security.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c28f2792");
  # https://blog.mozilla.org/security/2013/01/03/revoking-trust-in-two-turktrust-certficates/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d92931ec");
  script_set_attribute(attribute:"see_also", value:"http://www.turktrust.com.tr/kamuoyu-aciklamasi.2.html");


  script_set_attribute(attribute:"vuln_publication_date", value:"2012/12/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/01/07");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"General");

  script_copyright(english:"This script is Copyright (C) 2013-2020 Tenable Network Security, Inc.");

  script_dependencies("ssl_supported_versions.nasl");
  script_require_keys("Settings/ParanoidReport", "SSL/Supported");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("x509_func.inc");

function get_cn()
{
  local_var pair;

  foreach pair (_FCT_ANON_ARGS[0])
  {
    if (pair[0] == '2.5.4.3')
      return pair[1];
  }

  return NULL;
}

get_kb_item_or_exit("SSL/Supported");

# We don't have the full info for both certificates, so we're only
# checking whether DNs and CNs match.
if (report_paranoia < 2)
  audit(AUDIT_PARANOID);

# This is the DN of the legitimate CA.
ca_dn =  make_nested_list(
  make_list(
    '2.5.4.3',
    raw_string(
      "T",
      0xC3, 0x9C,
      "RKTRUST Elektronik Sunucu Sertifikas",
      0xC4, 0xB1,
      " Hizmetleri"
    )
  ),
  make_list(
    '2.5.4.6',
    'TR'
  ),
  make_list(
    '2.5.4.10',
    raw_string(
      "T",
      0xC3, 0x9C,
      "RKTRUST Bilgi",
      0xC4, 0xB0,
      "leti",
      0xC5, 0x9F,
      "im ve Bili",
      0xC5, 0x9F,
      "im G",
      0xC3, 0xBC,
      "venli",
      0xC4, 0x9F,
      "i Hizmetleri A.",
      0xC5, 0x9E,
      ". (c) Kas",
      0xC4, 0xB1,
      "m  2005"
    )
  )
);

# These are the CN portions of the DNs for the illegitimate
# intermediate CAs. We don't have full information for both.
im_ca_cn_1 = '*.EGO.GOV.TR';
im_ca_cn_2 = 'e-islem.kktcmerkezbankasi.org';

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

# What we're looking for is either the intermediate CAs themselves
# showing up in the certificate chain, or a certificate signed by the
# intermediate CAs.
#
# Start at the top since finding the intermediate CA is more important
# than finding a certificate is signed.
found = FALSE;
for (i = max_index(chain) - 1; i >= 0; i--)
{
  cert = chain[i]["tbsCertificate"];
  iss_cn = get_cn(cert["issuer"]);
  sub_cn = get_cn(cert["subject"]);
  bc = cert_get_ext(id:EXTN_BASIC_CONSTRAINTS, cert:cert);

  # Check if the cert is an illegitimate intermediate CA. Note that
  # when TURKTRUST reissues these certs, it won't cause a false
  # positive.
  if (
    obj_cmp(cert["issuer"], ca_dn) &&
    (sub_cn == im_ca_cn_1 || sub_cn == im_ca_cn_2) &&
    bc != NULL && bc["ca"]
  )
  {
    found = "intermediate";
    break;
  }

  # Check if the cert was issued by an illegitimate intermediate CA.
  if (iss_cn == im_ca_cn_1 || iss_cn == im_ca_cn_2)
  {
    found = "signed";
    break;
  }
}

if (!found)
  exit(0, "The certificate chain from port " + port + " is not affected.");

# Report our findings.
report = NULL;
if (report_verbosity > 0)
{
  if (found == "intermediate")
  {
    report =
      '\nThe following certificate is known to be an accidentally issued' +
      '\nillegitimate CA that cannot be trusted :';
  }
  else
  {
    report =
      '\nThe following certificate has been issued by an accidentally' +
      '\nissued illegitimate CA that cannot be trusted :';
  }

  report +=
    '\n' +
    '\n  Subject : ' + format_dn(cert["subject"]) +
    '\n  Issuer  : ' + format_dn(cert["issuer"]) +
    '\n';
}

security_warning(port:port, extra:report);
