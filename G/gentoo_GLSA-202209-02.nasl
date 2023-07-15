#%NASL_MIN_LEVEL 80900
#
# (C) Tenable, Inc.
#
# @NOAGENT@
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 202209-02.
#
# The advisory text is Copyright (C) 2001-2021 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include('compat.inc');

if (description)
{
  script_id(164805);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/09/07");

  script_cve_id(
    "CVE-2021-3711",
    "CVE-2021-3712",
    "CVE-2021-4104",
    "CVE-2021-29672",
    "CVE-2021-39048"
  );

  script_name(english:"GLSA-202209-02 : IBM Spectrum Protect: Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"");
  script_set_attribute(attribute:"description", value:
"The remote host is affected by the vulnerability described in GLSA-202209-02 (IBM Spectrum Protect: Multiple
Vulnerabilities)

  - IBM Spectrum Protect Client 8.1.0.0-8 through 1.11.0 is vulnerable to a stack-based buffer overflow,
    caused by improper bounds checking when processing the current locale settings. A local attacker could
    overflow a buffer and execute arbitrary code on the system with elevated privileges or cause the
    application to crash. IBM X-Force ID: 199479 (CVE-2021-29672)

  - In order to decrypt SM2 encrypted data an application is expected to call the API function
    EVP_PKEY_decrypt(). Typically an application will call this function twice. The first time, on entry, the
    out parameter can be NULL and, on exit, the outlen parameter is populated with the buffer size
    required to hold the decrypted plaintext. The application can then allocate a sufficiently sized buffer
    and call EVP_PKEY_decrypt() again, but this time passing a non-NULL value for the out parameter. A bug
    in the implementation of the SM2 decryption code means that the calculation of the buffer size required to
    hold the plaintext returned by the first call to EVP_PKEY_decrypt() can be smaller than the actual size
    required by the second call. This can lead to a buffer overflow when EVP_PKEY_decrypt() is called by the
    application a second time with a buffer that is too small. A malicious attacker who is able present SM2
    content for decryption to an application could cause attacker chosen data to overflow the buffer by up to
    a maximum of 62 bytes altering the contents of other data held after the buffer, possibly changing
    application behaviour or causing the application to crash. The location of the buffer is application
    dependent but is typically heap allocated. Fixed in OpenSSL 1.1.1l (Affected 1.1.1-1.1.1k).
    (CVE-2021-3711)

  - ASN.1 strings are represented internally within OpenSSL as an ASN1_STRING structure which contains a
    buffer holding the string data and a field holding the buffer length. This contrasts with normal C strings
    which are repesented as a buffer for the string data which is terminated with a NUL (0) byte. Although not
    a strict requirement, ASN.1 strings that are parsed using OpenSSL's own d2i functions (and other similar
    parsing functions) as well as any string whose value has been set with the ASN1_STRING_set() function will
    additionally NUL terminate the byte array in the ASN1_STRING structure. However, it is possible for
    applications to directly construct valid ASN1_STRING structures which do not NUL terminate the byte array
    by directly setting the data and length fields in the ASN1_STRING array. This can also happen by using
    the ASN1_STRING_set0() function. Numerous OpenSSL functions that print ASN.1 data have been found to
    assume that the ASN1_STRING byte array will be NUL terminated, even though this is not guaranteed for
    strings that have been directly constructed. Where an application requests an ASN.1 structure to be
    printed, and where that ASN.1 structure contains ASN1_STRINGs that have been directly constructed by the
    application without NUL terminating the data field, then a read buffer overrun can occur. The same thing
    can also occur during name constraints processing of certificates (for example if a certificate has been
    directly constructed by the application instead of loading it via the OpenSSL parsing functions, and the
    certificate contains non NUL terminated ASN1_STRING structures). It can also occur in the
    X509_get1_email(), X509_REQ_get1_email() and X509_get1_ocsp() functions. If a malicious actor can cause an
    application to directly construct an ASN1_STRING and then process it through one of the affected OpenSSL
    functions then this issue could be hit. This might result in a crash (causing a Denial of Service attack).
    It could also result in the disclosure of private memory contents (such as private keys, or sensitive
    plaintext). Fixed in OpenSSL 1.1.1l (Affected 1.1.1-1.1.1k). Fixed in OpenSSL 1.0.2za (Affected
    1.0.2-1.0.2y). (CVE-2021-3712)

  - IBM Spectrum Protect Client 7.1 and 8.1 is vulnerable to a stack based buffer overflow, caused by improper
    bounds checking. A local attacker could exploit this vulnerability and cause a denial of service. IBM
    X-Force ID: 214438. (CVE-2021-39048)

  - JMSAppender in Log4j 1.2 is vulnerable to deserialization of untrusted data when the attacker has write
    access to the Log4j configuration. The attacker can provide TopicBindingName and
    TopicConnectionFactoryBindingName configurations causing JMSAppender to perform JNDI requests that result
    in remote code execution in a similar fashion to CVE-2021-44228. Note this issue only affects Log4j 1.2
    when specifically configured to use JMSAppender, which is not the default. Apache Log4j 1.2 reached end of
    life in August 2015. Users should upgrade to Log4j 2 as it addresses numerous other issues from the
    previous versions. (CVE-2021-4104)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://security.gentoo.org/glsa/202209-02");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=788115");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=829189");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=831509");
  script_set_attribute(attribute:"solution", value:
"All IBM Spectrum Protect users should upgrade to the latest version:

          # emerge --sync
          # emerge --ask --oneshot --verbose >=app-backup/tsm-8.1.13.3");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-3711");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/02/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/09/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/09/07");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:tsm");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Gentoo Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/Gentoo/release", "Host/Gentoo/qpkg-list");

  exit(0);
}
include("qpkg.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/Gentoo/release")) audit(AUDIT_OS_NOT, "Gentoo");
if (!get_kb_item("Host/Gentoo/qpkg-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var flag = 0;

var packages = [
  {
    'name' : "app-backup/tsm",
    'unaffected' : make_list("ge 8.1.13.3", "lt 8.0.0"),
    'vulnerable' : make_list("lt 8.1.13.3")
  }
];

foreach package( packages ) {
  if (isnull(package['unaffected'])) package['unaffected'] = make_list();
  if (isnull(package['vulnerable'])) package['vulnerable'] = make_list();
  if (qpkg_check(package: package['name'] , unaffected: package['unaffected'], vulnerable: package['vulnerable'])) flag++;
}

# This plugin has a different number of unaffected and vulnerable versions for
# one or more packages. To ensure proper detection, a separate line should be 
# used for each fixed/vulnerable version pair.

if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_HOLE,
    extra      : qpkg_report_get()
  );
  exit(0);
}
else
{
  qpkg_tests = list_uniq(qpkg_tests);
  var tested = qpkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "IBM Spectrum Protect");
}
