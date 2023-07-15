##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux 2 Security Advisory ALAS-2021-1612.
##

include('compat.inc');

if (description)
{
  script_id(147910);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/21");

  script_cve_id("CVE-2021-23839", "CVE-2021-23840", "CVE-2021-23841");
  script_xref(name:"ALAS", value:"2021-1612");
  script_xref(name:"CEA-ID", value:"CEA-2021-0025");

  script_name(english:"Amazon Linux 2 : openssl11 (ALAS-2021-1612)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Amazon Linux 2 host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The version of openssl11 installed on the remote host is prior to 1.1.1g-12. It is, therefore, affected by multiple
vulnerabilities as referenced in the ALAS2-2021-1612 advisory.

  - OpenSSL 1.0.2 supports SSLv2. If a client attempts to negotiate SSLv2 with a server that is configured to
    support both SSLv2 and more recent SSL and TLS versions then a check is made for a version rollback attack
    when unpadding an RSA signature. Clients that support SSL or TLS versions greater than SSLv2 are supposed
    to use a special form of padding. A server that supports greater than SSLv2 is supposed to reject
    connection attempts from a client where this special form of padding is present, because this indicates
    that a version rollback has occurred (i.e. both client and server support greater than SSLv2, and yet this
    is the version that is being requested). The implementation of this padding check inverted the logic so
    that the connection attempt is accepted if the padding is present, and rejected if it is absent. This
    means that such as server will accept a connection if a version rollback attack has occurred. Further the
    server will erroneously reject a connection if a normal SSLv2 connection attempt is made. Only OpenSSL
    1.0.2 servers from version 1.0.2s to 1.0.2x are affected by this issue. In order to be vulnerable a 1.0.2
    server must: 1) have configured SSLv2 support at compile time (this is off by default), 2) have configured
    SSLv2 support at runtime (this is off by default), 3) have configured SSLv2 ciphersuites (these are not in
    the default ciphersuite list) OpenSSL 1.1.1 does not have SSLv2 support and therefore is not vulnerable to
    this issue. The underlying error is in the implementation of the RSA_padding_check_SSLv23() function. This
    also affects the RSA_SSLV23_PADDING padding mode used by various other functions. Although 1.1.1 does not
    support SSLv2 the RSA_padding_check_SSLv23() function still exists, as does the RSA_SSLV23_PADDING padding
    mode. Applications that directly call that function or use that padding mode will encounter this issue.
    However since there is no support for the SSLv2 protocol in 1.1.1 this is considered a bug and not a
    security issue in that version. OpenSSL 1.0.2 is out of support and no longer receiving public updates.
    Premium support customers of OpenSSL 1.0.2 should upgrade to 1.0.2y. Other users should upgrade to 1.1.1j.
    Fixed in OpenSSL 1.0.2y (Affected 1.0.2s-1.0.2x). (CVE-2021-23839)

  - Calls to EVP_CipherUpdate, EVP_EncryptUpdate and EVP_DecryptUpdate may overflow the output length argument
    in some cases where the input length is close to the maximum permissable length for an integer on the
    platform. In such cases the return value from the function call will be 1 (indicating success), but the
    output length value will be negative. This could cause applications to behave incorrectly or crash.
    OpenSSL versions 1.1.1i and below are affected by this issue. Users of these versions should upgrade to
    OpenSSL 1.1.1j. OpenSSL versions 1.0.2x and below are affected by this issue. However OpenSSL 1.0.2 is out
    of support and no longer receiving public updates. Premium support customers of OpenSSL 1.0.2 should
    upgrade to 1.0.2y. Other users should upgrade to 1.1.1j. Fixed in OpenSSL 1.1.1j (Affected 1.1.1-1.1.1i).
    Fixed in OpenSSL 1.0.2y (Affected 1.0.2-1.0.2x). (CVE-2021-23840)

  - The OpenSSL public API function X509_issuer_and_serial_hash() attempts to create a unique hash value based
    on the issuer and serial number data contained within an X509 certificate. However it fails to correctly
    handle any errors that may occur while parsing the issuer field (which might occur if the issuer field is
    maliciously constructed). This may subsequently result in a NULL pointer deref and a crash leading to a
    potential denial of service attack. The function X509_issuer_and_serial_hash() is never directly called by
    OpenSSL itself so applications are only vulnerable if they use this function directly and they use it on
    certificates that may have been obtained from untrusted sources. OpenSSL versions 1.1.1i and below are
    affected by this issue. Users of these versions should upgrade to OpenSSL 1.1.1j. OpenSSL versions 1.0.2x
    and below are affected by this issue. However OpenSSL 1.0.2 is out of support and no longer receiving
    public updates. Premium support customers of OpenSSL 1.0.2 should upgrade to 1.0.2y. Other users should
    upgrade to 1.1.1j. Fixed in OpenSSL 1.1.1j (Affected 1.1.1-1.1.1i). Fixed in OpenSSL 1.0.2y (Affected
    1.0.2-1.0.2x). (CVE-2021-23841)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/AL2/ALAS-2021-1612.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/../../faqs.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-23839.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-23840.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-23841.html");
  script_set_attribute(attribute:"solution", value:
"Run 'yum update openssl11' to update your system.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-23839");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/02/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/03/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/03/19");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:openssl11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:openssl11-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:openssl11-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:openssl11-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:openssl11-static");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux:2");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Amazon Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/AmazonLinux/release", "Host/AmazonLinux/rpm-list");

  exit(0);
}

include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

var alas_release = get_kb_item("Host/AmazonLinux/release");
if (isnull(alas_release) || !strlen(alas_release)) audit(AUDIT_OS_NOT, "Amazon Linux");
var os_ver = pregmatch(pattern: "^AL(A|\d+|-\d+)", string:alas_release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Amazon Linux");
os_ver = os_ver[1];
if (os_ver != "2")
{
  if (os_ver == 'A') os_ver = 'AMI';
  audit(AUDIT_OS_NOT, "Amazon Linux 2", "Amazon Linux " + os_ver);
}

if (!get_kb_item("Host/AmazonLinux/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var pkgs = [
    {'reference':'openssl11-1.1.1g-12.amzn2.0.2', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'openssl11-1.1.1g-12.amzn2.0.2', 'cpu':'i686', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'openssl11-1.1.1g-12.amzn2.0.2', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'openssl11-debuginfo-1.1.1g-12.amzn2.0.2', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'openssl11-debuginfo-1.1.1g-12.amzn2.0.2', 'cpu':'i686', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'openssl11-debuginfo-1.1.1g-12.amzn2.0.2', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'openssl11-devel-1.1.1g-12.amzn2.0.2', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'openssl11-devel-1.1.1g-12.amzn2.0.2', 'cpu':'i686', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'openssl11-devel-1.1.1g-12.amzn2.0.2', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'openssl11-libs-1.1.1g-12.amzn2.0.2', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'openssl11-libs-1.1.1g-12.amzn2.0.2', 'cpu':'i686', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'openssl11-libs-1.1.1g-12.amzn2.0.2', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'openssl11-static-1.1.1g-12.amzn2.0.2', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'openssl11-static-1.1.1g-12.amzn2.0.2', 'cpu':'i686', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'openssl11-static-1.1.1g-12.amzn2.0.2', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE}
];

var flag = 0;
foreach var package_array ( pkgs ) {
  var reference = NULL;
  var _release = NULL;
  var sp = NULL;
  var _cpu = NULL;
  var el_string = NULL;
  var rpm_spec_vers_cmp = NULL;
  var epoch = NULL;
  var allowmaj = NULL;
  var exists_check = NULL;
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (!empty_or_null(package_array['release'])) _release = package_array['release'];
  if (!empty_or_null(package_array['sp'])) sp = package_array['sp'];
  if (!empty_or_null(package_array['cpu'])) _cpu = package_array['cpu'];
  if (!empty_or_null(package_array['el_string'])) el_string = package_array['el_string'];
  if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
  if (!empty_or_null(package_array['epoch'])) epoch = package_array['epoch'];
  if (!empty_or_null(package_array['allowmaj'])) allowmaj = package_array['allowmaj'];
  if (!empty_or_null(package_array['exists_check'])) exists_check = package_array['exists_check'];
  if (reference && _release && (!exists_check || rpm_exists(release:_release, rpm:exists_check))) {
    if (rpm_check(release:_release, sp:sp, cpu:_cpu, reference:reference, epoch:epoch, el_string:el_string, rpm_spec_vers_cmp:rpm_spec_vers_cmp, allowmaj:allowmaj)) flag++;
  }
}

if (flag)
{
  security_report_v4(
      port       : 0,
      severity   : SECURITY_WARNING,
      extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "openssl11 / openssl11-debuginfo / openssl11-devel / etc");
}