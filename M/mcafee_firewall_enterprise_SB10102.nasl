#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(81815);
  script_version("1.17");
  script_cvs_date("Date: 2019/11/22");

  script_cve_id(
    "CVE-2014-3569",
    "CVE-2014-3570",
    "CVE-2014-3571",
    "CVE-2014-3572",
    "CVE-2014-8275",
    "CVE-2015-0204",
    "CVE-2015-0205",
    "CVE-2015-0206"
  );
  script_bugtraq_id(
    71934,
    71935,
    71936,
    71937,
    71939,
    71940,
    71941,
    71942
  );
  script_xref(name:"CERT", value:"243585");
  script_xref(name:"MCAFEE-SB", value:"SB10102");

  script_name(english:"McAfee Firewall Enterprise OpenSSL Multiple Vulnerabilities (SB10102) (FREAK)");
  script_summary(english:"Checks the version of MFE.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote host has a version of McAfee Firewall Enterprise installed
that is affected by multiple vulnerabilities in the OpenSSL library :

  - A NULL pointer dereference flaw exists when the SSLv3
    option isn't enabled and an SSLv3 ClientHello is
    received. This allows a remote attacker, using an
    unexpected handshake, to crash the daemon, resulting in
    a denial of service. (CVE-2014-3569)

  - The BIGNUM squaring (BN_sqr) implementation does not
    properly calculate the square of a BIGNUM value. This
    allows a remote attacker to defeat cryptographic
    protection mechanisms. (CVE-2014-3570)

  - A NULL pointer dereference flaw exists with
    dtls1_get_record() when handling DTLS messages. A remote
    attacker, using a specially crafted DTLS message, can
    cause a denial of service. (CVE-2014-3571)

  - A flaw exists with ECDH handshakes when using an ECDSA
    certificate without a ServerKeyExchange message. This
    allows a remote attacker to trigger a loss of forward
    secrecy from the ciphersuite. (CVE-2014-3572)

  - A flaw exists when accepting non-DER variations of
    certificate signature algorithms and signature encodings
    due to a lack of enforcement of matches between signed
    and unsigned portions. A remote attacker, by including
    crafted data within a certificate's unsigned portion,
    can bypass fingerprint-based certificate-blacklist
    protection mechanisms. (CVE-2014-8275)

  - A security feature bypass vulnerability, known as FREAK
    (Factoring attack on RSA-EXPORT Keys), exists due to the
    support of weak EXPORT_RSA cipher suites with keys less
    than or equal to 512 bits. A man-in-the-middle attacker
    may be able to downgrade the SSL/TLS connection to use
    EXPORT_RSA cipher suites which can be factored in a
    short amount of time, allowing the attacker to intercept
    and decrypt the traffic. (CVE-2015-0204)

  - A flaw exists when accepting DH certificates for client
    authentication without the CertificateVerify message.
    This allows a remote attacker to authenticate to the
    service without a private key. (CVE-2015-0205)

  - A memory leak occurs in dtls1_buffer_record()
    when handling a saturation of DTLS records containing
    the same number sequence but for the next epoch. This
    allows a remote attacker to cause a denial of service.
    (CVE-2015-0206)");
  script_set_attribute(attribute:"see_also", value:"https://kc.mcafee.com/corporate/index?page=content&id=SB10102");
  script_set_attribute(attribute:"see_also", value:"https://www.smacktls.com/#freak");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch referenced in the vendor security
advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:L/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2015-0205");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"in_the_news", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/10/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/03/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/03/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/a:mcafee:firewall_enterprise");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Firewalls");

  script_copyright(english:"This script is Copyright (C) 2015-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("mcafee_firewall_enterprise_version.nbin");
  script_require_keys("Host/McAfeeFE/version", "Host/McAfeeFE/version_display", "Host/McAfeeFE/installed_patches");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

app_name = "McAfee Firewall Enterprise";
version = get_kb_item_or_exit("Host/McAfeeFE/version");
version_display = get_kb_item_or_exit("Host/McAfeeFE/version_display");
installed_patches = get_kb_item_or_exit("Host/McAfeeFE/installed_patches");

hotfixmap = make_array(
  "^7\."    , "70103E65"  ,
  "^8\.2\.1(\.|$)"   , "8.2.1E133" ,
  "^8\.3\.1(\.|$)"   , "8.3.1E68"  ,
  "^8\.3\.2(\.|$)"   , "8.3.2E37"
);

disp_name = make_array(
  "70103E65"  , "7.0.1.03 ePatch 65",
  "8.2.1E133" , "8.2.1 ePatch 133",
  "8.3.1E68"  , "8.3.1 ePatch 68",
  "8.3.2E37"  , "8.3.2 ePatch 37"
);

hotfix = NULL;
name   = NULL;

foreach vergx (keys(hotfixmap))
{
  if(version =~ vergx)
  {
    hotfix = hotfixmap[vergx ];
    name   = disp_name[hotfix];
    break;
  }
}

if(isnull(hotfix) || (hotfix =~ "(^|,)[\d\.]+?E\d+?($|,)" && installed_patches !~ "(^|,)[\d\.]+?E\d+?($|,)"))
  audit(AUDIT_INST_VER_NOT_VULN, version_display);

if (hotfix >!< installed_patches)
{
  port = 0;

  if (report_verbosity > 0)
  {
    report = 
      '\n  Installed Version : ' + version_display +
      '\n  Patched Version   : ' + name +
      '\n';
    security_warning(extra:report, port:port);
  }
  else security_warning(port);
  exit(0);
}
else audit(AUDIT_PATCH_INSTALLED, name, app_name);
