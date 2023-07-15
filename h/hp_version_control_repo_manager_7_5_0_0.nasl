#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(85802);
  script_version("1.8");
  script_cvs_date("Date: 2018/11/15 20:50:27");

  script_cve_id(
    "CVE-2014-3569",
    "CVE-2014-3570",
    "CVE-2014-3571",
    "CVE-2014-3572",
    "CVE-2014-8275",
    "CVE-2015-0204",
    "CVE-2015-0205",
    "CVE-2015-0206",
    "CVE-2015-5409",
    "CVE-2015-5410",
    "CVE-2015-5411",
    "CVE-2015-5412",
    "CVE-2015-5413"
  );
  script_bugtraq_id(
    71941,
    71942,
    71936,
    71939,
    71940,
    71934,
    71935,
    71937
  );
  script_xref(name:"CERT", value:"243585");
  script_xref(name:"HP", value:"emr_na-c04765115");
  script_xref(name:"HP", value:"HPSBMU03396");

  script_name(english:"HP Version Control Repository Manager < 7.5.0 Multiple Vulnerabilities (HPSBMU03396) (FREAK)");
  script_summary(english:"Checks the version of HP VCRM.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has an application installed that is affected
by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of HP Version Control Repository Manager (VCRM) installed
on the remote Windows host is prior to 7.5.0. It is, therefore,
affected by multiple vulnerabilities :

  - A NULL pointer dereference flaw exists when the SSLv3
    option isn't enabled and an SSLv3 ClientHello is
    received. This allows a remote attacker, using an
    unexpected handshake, to crash the daemon, resulting in
    a denial of service. (CVE-2014-3569)

  - The BIGNUM squaring (BN_sqr) implementation does not
    properly calculate the square of a BIGNUM value. This
    allows remote attackers to defeat cryptographic
    protection mechanisms. (CVE-2014-3570)

  - A NULL pointer dereference flaw exists in the
    dtls1_get_record() function when handling DTLS messages.
    A remote attacker, using a specially crafted DTLS
    message, can cause a denial of service. (CVE-2014-3571)

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

  - A memory leak occurs in dtls1_buffer_record() when
    handling a saturation of DTLS records containing the
    same number sequence but for the next epoch. This allows
    a remote attacker to cause a denial of service.
    (CVE-2015-0206)

  - An unspecified buffer overflow condition exists in VCRM
    due to improper validation of user-supplied input. A
    remote, authenticated attacker can exploit this to cause
    a denial of service or execute arbitrary code.
    (CVE-2015-5409)

  - An unspecified flaw exists in VCRM that allows a remote,
    authenticated attacker to modify values without proper
    authorization, gain unspecified access, cause a denial of
    service, or execute arbitrary code. (CVE-2015-5410)

  - An unspecified flaw exists in VCRM that allows a remote,
    authenticated attacker to gain access to sensitive
    information. (CVE-2015-5411, CVE-2015-5413)

  - A flaw exists in VCRM when handling certain sensitive
    actions due to HTTP requests not requiring multiple
    steps, explicit confirmation, or a unique token. A
    remote, authenticated attacker can exploit this to
    conduct a cross-site request forgery attack via a
    specially crafted link. (CVE-2015-5412)");
  # https://support.hpe.com/hpsc/doc/public/display?docId=emr_na-c04765115
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?1b9cb578");
  script_set_attribute(attribute:"see_also", value:"https://www.openssl.org/news/secadv/20150108.txt");
  script_set_attribute(attribute:"see_also", value:"https://www.smacktls.com/#freak");
  script_set_attribute(attribute:"solution", value:
"Upgrade to HP Version Control Repository Manager 7.5.0 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:P/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/10/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/08/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/09/04");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:hp:version_control_repository_manager");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2015-2018 Tenable Network Security, Inc.");

  script_dependencies("hp_version_control_repo_manager_installed.nbin");
  script_require_keys("installed_sw/HP Version Control Repository Manager");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("install_func.inc");

appname = "HP Version Control Repository Manager";
install = get_single_install(app_name:appname, exit_if_unknown_ver:TRUE);
version = install['version'];
path = install['path'];

if (ver_compare(ver:version, fix:'7.5.0.0', strict:FALSE) < 0)
{
  port = get_kb_item("SMB/transport");
  if (!port) port = 445;

  if (report_verbosity > 0)
  {
    report =
      '\n  Path              : ' + path +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : 7.5.0.0' +
      '\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
  exit(0);
}
else audit(AUDIT_INST_PATH_NOT_VULN, appname, version, path);
