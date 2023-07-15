#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux 2022 Security Advisory ALAS2022-2022-104.
##

include('compat.inc');

if (description)
{
  script_id(164775);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/09/13");

  script_cve_id(
    "CVE-2022-1292",
    "CVE-2022-1343",
    "CVE-2022-1434",
    "CVE-2022-1473"
  );
  script_xref(name:"IAVA", value:"2022-A-0186-S");

  script_name(english:"Amazon Linux 2022 : openssl (ALAS2022-2022-104)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Amazon Linux 2022 host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The version of openssl installed on the remote host is prior to 3.0.3-1. It is, therefore, affected by multiple
vulnerabilities as referenced in the ALAS2022-2022-104 advisory.

  - The c_rehash script does not properly sanitise shell metacharacters to prevent command injection. This
    script is distributed by some operating systems in a manner where it is automatically executed. On such
    operating systems, an attacker could execute arbitrary commands with the privileges of the script. Use of
    the c_rehash script is considered obsolete and should be replaced by the OpenSSL rehash command line tool.
    Fixed in OpenSSL 3.0.3 (Affected 3.0.0,3.0.1,3.0.2). Fixed in OpenSSL 1.1.1o (Affected 1.1.1-1.1.1n).
    Fixed in OpenSSL 1.0.2ze (Affected 1.0.2-1.0.2zd). (CVE-2022-1292)

  - The function `OCSP_basic_verify` verifies the signer certificate on an OCSP response. In the case where
    the (non-default) flag OCSP_NOCHECKS is used then the response will be positive (meaning a successful
    verification) even in the case where the response signing certificate fails to verify. It is anticipated
    that most users of `OCSP_basic_verify` will not use the OCSP_NOCHECKS flag. In this case the
    `OCSP_basic_verify` function will return a negative value (indicating a fatal error) in the case of a
    certificate verification failure. The normal expected return value in this case would be 0. This issue
    also impacts the command line OpenSSL ocsp application. When verifying an ocsp response with the
    -no_cert_checks option the command line application will report that the verification is successful even
    though it has in fact failed. In this case the incorrect successful response will also be accompanied by
    error messages showing the failure and contradicting the apparently successful result. Fixed in OpenSSL
    3.0.3 (Affected 3.0.0,3.0.1,3.0.2). (CVE-2022-1343)

  - The OpenSSL 3.0 implementation of the RC4-MD5 ciphersuite incorrectly uses the AAD data as the MAC key.
    This makes the MAC key trivially predictable. An attacker could exploit this issue by performing a man-in-
    the-middle attack to modify data being sent from one endpoint to an OpenSSL 3.0 recipient such that the
    modified data would still pass the MAC integrity check. Note that data sent from an OpenSSL 3.0 endpoint
    to a non-OpenSSL 3.0 endpoint will always be rejected by the recipient and the connection will fail at
    that point. Many application protocols require data to be sent from the client to the server first.
    Therefore, in such a case, only an OpenSSL 3.0 server would be impacted when talking to a non-OpenSSL 3.0
    client. If both endpoints are OpenSSL 3.0 then the attacker could modify data being sent in both
    directions. In this case both clients and servers could be affected, regardless of the application
    protocol. Note that in the absence of an attacker this bug means that an OpenSSL 3.0 endpoint
    communicating with a non-OpenSSL 3.0 endpoint will fail to complete the handshake when using this
    ciphersuite. The confidentiality of data is not impacted by this issue, i.e. an attacker cannot decrypt
    data that has been encrypted using this ciphersuite - they can only modify it. In order for this attack to
    work both endpoints must legitimately negotiate the RC4-MD5 ciphersuite. This ciphersuite is not compiled
    by default in OpenSSL 3.0, and is not available within the default provider or the default ciphersuite
    list. This ciphersuite will never be used if TLSv1.3 has been negotiated. In order for an OpenSSL 3.0
    endpoint to use this ciphersuite the following must have occurred: 1) OpenSSL must have been compiled with
    the (non-default) compile time option enable-weak-ssl-ciphers 2) OpenSSL must have had the legacy provider
    explicitly loaded (either through application code or via configuration) 3) The ciphersuite must have been
    explicitly added to the ciphersuite list 4) The libssl security level must have been set to 0 (default is
    1) 5) A version of SSL/TLS below TLSv1.3 must have been negotiated 6) Both endpoints must negotiate the
    RC4-MD5 ciphersuite in preference to any others that both endpoints have in common Fixed in OpenSSL 3.0.3
    (Affected 3.0.0,3.0.1,3.0.2). (CVE-2022-1434)

  - The OPENSSL_LH_flush() function, which empties a hash table, contains a bug that breaks reuse of the
    memory occuppied by the removed hash table entries. This function is used when decoding certificates or
    keys. If a long lived process periodically decodes certificates or keys its memory usage will expand
    without bounds and the process might be terminated by the operating system causing a denial of service.
    Also traversing the empty hash table entries will take increasingly more time. Typically such long lived
    processes might be TLS clients or TLS servers configured to accept client certificate authentication. The
    function was added in the OpenSSL 3.0 version thus older releases are not affected by the issue. Fixed in
    OpenSSL 3.0.3 (Affected 3.0.0,3.0.1,3.0.2). (CVE-2022-1473)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/AL2022/ALAS-2022-104.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-1292.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-1343.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-1434.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-1473.html");
  script_set_attribute(attribute:"solution", value:
"Run 'yum update openssl' to update your system.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-1292");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/05/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/07/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/09/07");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:openssl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:openssl-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:openssl-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:openssl-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:openssl-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:openssl-libs-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:openssl-perl");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux:2022");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Amazon Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/AmazonLinux/release", "Host/AmazonLinux/rpm-list");

  exit(0);
}

include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

var release = get_kb_item("Host/AmazonLinux/release");
if (isnull(release) || !strlen(release)) audit(AUDIT_OS_NOT, "Amazon Linux");
var os_ver = pregmatch(pattern: "^AL(A|\d+|-\d+)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Amazon Linux");
var os_ver = os_ver[1];
if (os_ver != "-2022")
{
  if (os_ver == 'A') os_ver = 'AMI';
  audit(AUDIT_OS_NOT, "Amazon Linux 2022", "Amazon Linux " + os_ver);
}

if (!get_kb_item("Host/AmazonLinux/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var pkgs = [
    {'reference':'openssl-3.0.3-1.amzn2022.0.1', 'cpu':'aarch64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'openssl-3.0.3-1.amzn2022.0.1', 'cpu':'i686', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'openssl-3.0.3-1.amzn2022.0.1', 'cpu':'x86_64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'openssl-debuginfo-3.0.3-1.amzn2022.0.1', 'cpu':'aarch64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'openssl-debuginfo-3.0.3-1.amzn2022.0.1', 'cpu':'i686', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'openssl-debuginfo-3.0.3-1.amzn2022.0.1', 'cpu':'x86_64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'openssl-debugsource-3.0.3-1.amzn2022.0.1', 'cpu':'aarch64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'openssl-debugsource-3.0.3-1.amzn2022.0.1', 'cpu':'i686', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'openssl-debugsource-3.0.3-1.amzn2022.0.1', 'cpu':'x86_64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'openssl-devel-3.0.3-1.amzn2022.0.1', 'cpu':'aarch64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'openssl-devel-3.0.3-1.amzn2022.0.1', 'cpu':'i686', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'openssl-devel-3.0.3-1.amzn2022.0.1', 'cpu':'x86_64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'openssl-libs-3.0.3-1.amzn2022.0.1', 'cpu':'aarch64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'openssl-libs-3.0.3-1.amzn2022.0.1', 'cpu':'i686', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'openssl-libs-3.0.3-1.amzn2022.0.1', 'cpu':'x86_64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'openssl-libs-debuginfo-3.0.3-1.amzn2022.0.1', 'cpu':'aarch64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'openssl-libs-debuginfo-3.0.3-1.amzn2022.0.1', 'cpu':'i686', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'openssl-libs-debuginfo-3.0.3-1.amzn2022.0.1', 'cpu':'x86_64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'openssl-perl-3.0.3-1.amzn2022.0.1', 'cpu':'aarch64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'openssl-perl-3.0.3-1.amzn2022.0.1', 'cpu':'i686', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'openssl-perl-3.0.3-1.amzn2022.0.1', 'cpu':'x86_64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE}
];

var flag = 0;
foreach var package_array ( pkgs ) {
  var reference = NULL;
  var release = NULL;
  var sp = NULL;
  var cpu = NULL;
  var el_string = NULL;
  var rpm_spec_vers_cmp = NULL;
  var epoch = NULL;
  var allowmaj = NULL;
  var exists_check = NULL;
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (!empty_or_null(package_array['release'])) release = package_array['release'];
  if (!empty_or_null(package_array['sp'])) sp = package_array['sp'];
  if (!empty_or_null(package_array['cpu'])) cpu = package_array['cpu'];
  if (!empty_or_null(package_array['el_string'])) el_string = package_array['el_string'];
  if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
  if (!empty_or_null(package_array['epoch'])) epoch = package_array['epoch'];
  if (!empty_or_null(package_array['allowmaj'])) allowmaj = package_array['allowmaj'];
  if (!empty_or_null(package_array['exists_check'])) exists_check = package_array['exists_check'];
  if (reference && release && (!exists_check || rpm_exists(release:release, rpm:exists_check))) {
    if (rpm_check(release:release, sp:sp, cpu:cpu, reference:reference, epoch:epoch, el_string:el_string, rpm_spec_vers_cmp:rpm_spec_vers_cmp, allowmaj:allowmaj)) flag++;
  }
}

if (flag)
{
  security_report_v4(
      port       : 0,
      severity   : SECURITY_HOLE,
      extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "openssl / openssl-debuginfo / openssl-debugsource / etc");
}