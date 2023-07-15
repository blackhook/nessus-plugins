#TRUSTED 168cee9d349a90c4c66dd321ac31282a4010a5d4bbb4286c360527e3dbc69c712981be3ebdb98b5158d9b90611e3934102255095de818a3a533a9e97a403d8fd7d2bd036eb7da2bad6d06744f5462411c81954d0e628e538ea0959e039fc6305aa5f1244aa9a46be7d27445cab4bac6158648a62998ce282f93d3e185574f719dc8d5b9bf0f2982268ce6c9571218d786f6936959594f6450c321e3a390bacab9eeff1fc03f6248e3f591af744fc7e8b5412ec92c282ed0623784b3e4588119757e9e599d653c683f050060e9951e58963020f48391e9132ca3519e46ab47fb85bd43c90a68cab35890283f3a7ed8f37d6fceeeb04e0216bc0ccfabae3cdaf5aaf4165c5d94ad99c0ed2835f1fef2dac9eb74e4fb960e35185defb526844adfb6441ca934e2144a4376a5decda1b6a28cb51116b7356d606f106b7f452eda111a803f921ff4c1040a40dd4ad46c9a6a4dd258120bbc203297f9ee215b8b35f9b17ba336a7fc70ba2176a54823650ac1f569b551184bd765265d869e52e19b8297555084ad9f98f3a13c2c98cdd4cdb21e529737ce29261a8851c6bf8f50c758f097065da78debd9f448e1be9364747f47fbf00619e409b60044170ffa7238a547221562822ada7149aad8a9be52cbbb0f21d3b0f7c748f3b691f254bdea9d86ece9e6496113655939ad4d0324c8fcd943f7bb3ce25f423ae2a481a33425be9f4
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(82912);
  script_version("1.12");
  script_set_attribute(attribute:"plugin_modification_date", value:"2018/07/12");

  script_cve_id(
    "CVE-2014-3569",
    "CVE-2014-3570",
    "CVE-2014-3572",
    "CVE-2014-8275",
    "CVE-2015-0204",
    "CVE-2015-0205"
  );
  script_bugtraq_id(71934, 71935, 71936, 71939, 71941, 71942);
  script_xref(name:"JSA", value:"JSA10679");
  script_xref(name:"CERT", value:"243585");

  script_name(english:"Juniper Junos Multiple OpenSSL Vulnerabilities (JSA10679) (FREAK)");
  script_summary(english:"Checks the Junos version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the remote Juniper
Junos device is affected by the following vulnerabilities related to
OpenSSL :

  - A NULL pointer dereference flaw exists when the SSLv3
    option isn't enabled and an SSLv3 ClientHello is
    received. This allows a remote attacker, using an
    unexpected handshake, to crash the daemon, resulting in
    a denial of service. (CVE-2014-3569)

  - The BIGNUM squaring (BN_sqr) implementation does not
    properly calculate the square of a BIGNUM value. This
    allows remote attackers to defeat cryptographic
    protection mechanisms. (CVE-2014-3570)

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

Note that these issues only affects devices with J-Web or the SSL
service for JUNOScript enabled.");

  script_set_attribute(attribute:"see_also", value:"https://kb.juniper.net/InfoCenter/index?page=content&id=JSA10679");
  script_set_attribute(attribute:"see_also", value:"https://www.openssl.org/news/secadv/20150108.txt");
  script_set_attribute(attribute:"see_also", value:"https://www.smacktls.com/#freak");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant Junos software release or workaround referenced in
Juniper advisory JSA10679.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/10/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/04/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/04/21");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:juniper:junos");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:openssl:openssl");
  script_set_attribute(attribute:"in_the_news", value:"true");
  
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Junos Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2015-2018 Tenable Network Security, Inc.");

  script_dependencies("junos_version.nasl");
  script_require_keys("Host/Juniper/JUNOS/Version");

  exit(0);
}

include("audit.inc");
include("junos_kb_cmd_func.inc");
include("misc_func.inc");

ver = get_kb_item_or_exit('Host/Juniper/JUNOS/Version');

fixes = make_array();
fixes['12.1X44'] = '12.1X44-D50';
fixes['12.1X46'] = '12.1X46-D35';
fixes['12.1X47'] = '12.1X47-D25';
fixes['12.3'] = '12.3R10';
fixes['12.3X48'] = '12.3X48-D10';
fixes['13.2'] = '13.2R8';
fixes['13.3'] = '13.3R6';
fixes['14.1'] = '14.1R5';
fixes['14.2'] = '14.2R3';

fix = check_junos(ver:ver, fixes:fixes, exit_on_fail:TRUE);

# HTTPS or XNM-SSL must be enabled
override = TRUE;
buf = junos_command_kb_item(cmd:"show configuration | display set");
if (buf)
{
  patterns = make_list(
    "^set system services web-management http(s)? interface", # J-Web
    "^set system services xnm-ssl" # SSL Service for JUNOScript (XNM-SSL)
  );
  foreach pattern (patterns)
  {
    if (junos_check_config(buf:buf, pattern:pattern))
    {
      override = FALSE;
      break;
    }
  }
  if (override)
    audit(AUDIT_HOST_NOT,
      'affected because J-Web and SSL Service for JUNOScript (XNM-SSL) are not enabled');
}

junos_report(ver:ver, fix:fix, override:override, severity:SECURITY_WARNING);
