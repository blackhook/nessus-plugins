#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux 2023 Security Advisory ALAS2023-2023-084.
##

include('compat.inc');

if (description)
{
  script_id(173113);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/21");

  script_cve_id(
    "CVE-2021-22959",
    "CVE-2021-22960",
    "CVE-2021-43616",
    "CVE-2021-44531",
    "CVE-2021-44532",
    "CVE-2021-44533",
    "CVE-2022-3602",
    "CVE-2022-3786",
    "CVE-2022-21824",
    "CVE-2022-32212",
    "CVE-2022-32213",
    "CVE-2022-32214",
    "CVE-2022-32215",
    "CVE-2022-32222",
    "CVE-2022-32223",
    "CVE-2022-35255",
    "CVE-2022-35256",
    "CVE-2022-43548"
  );
  script_xref(name:"CEA-ID", value:"CEA-2022-0036");

  script_name(english:"Amazon Linux 2023 : nodejs, nodejs-devel, nodejs-full-i18n (ALAS2023-2023-084)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Amazon Linux 2023 host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"It is, therefore, affected by multiple vulnerabilities as referenced in the ALAS2023-2023-084 advisory.

  - The parser in accepts requests with a space (SP) right after the header name before the colon. This can
    lead to HTTP Request Smuggling (HRS) in llhttp < v2.1.4 and < v6.0.6. (CVE-2021-22959)

  - The parse function in llhttp < 2.1.4 and < 6.0.6. ignores chunk extensions when parsing the body of
    chunked requests. This leads to HTTP Request Smuggling (HRS) under certain conditions. (CVE-2021-22960)

  - ** DISPUTED ** The npm ci command in npm 7.x and 8.x through 8.1.3 proceeds with an installation even if
    dependency information in package-lock.json differs from package.json. This behavior is inconsistent with
    the documentation, and makes it easier for attackers to install malware that was supposed to have been
    blocked by an exact version match requirement in package-lock.json. NOTE: The npm team believes this is
    not a vulnerability. It would require someone to socially engineer package.json which has different
    dependencies than package-lock.json. That user would have to have file system or write access to change
    dependencies. The npm team states preventing malicious actors from socially engineering or gaining file
    system access is outside the scope of the npm CLI. (CVE-2021-43616)

  - Accepting arbitrary Subject Alternative Name (SAN) types, unless a PKI is specifically defined to use a
    particular SAN type, can result in bypassing name-constrained intermediates. Node.js < 12.22.9, < 14.18.3,
    < 16.13.2, and < 17.3.1 was accepting URI SAN types, which PKIs are often not defined to use.
    Additionally, when a protocol allows URI SANs, Node.js did not match the URI correctly.Versions of Node.js
    with the fix for this disable the URI SAN type when checking a certificate against a hostname. This
    behavior can be reverted through the --security-revert command-line option. (CVE-2021-44531)

  - Node.js < 12.22.9, < 14.18.3, < 16.13.2, and < 17.3.1 converts SANs (Subject Alternative Names) to a
    string format. It uses this string to check peer certificates against hostnames when validating
    connections. The string format was subject to an injection vulnerability when name constraints were used
    within a certificate chain, allowing the bypass of these name constraints.Versions of Node.js with the fix
    for this escape SANs containing the problematic characters in order to prevent the injection. This
    behavior can be reverted through the --security-revert command-line option. (CVE-2021-44532)

  - Node.js < 12.22.9, < 14.18.3, < 16.13.2, and < 17.3.1 did not handle multi-value Relative Distinguished
    Names correctly. Attackers could craft certificate subjects containing a single-value Relative
    Distinguished Name that would be interpreted as a multi-value Relative Distinguished Name, for example, in
    order to inject a Common Name that would allow bypassing the certificate subject verification.Affected
    versions of Node.js that do not accept multi-value Relative Distinguished Names and are thus not
    vulnerable to such attacks themselves. However, third-party code that uses node's ambiguous presentation
    of certificate subjects may be vulnerable. (CVE-2021-44533)

  - Due to the formatting logic of the console.table() function it was not safe to allow user controlled
    input to be passed to the properties parameter while simultaneously passing a plain object with at least
    one property as the first parameter, which could be __proto__. The prototype pollution has very limited
    control, in that it only allows an empty string to be assigned to numerical keys of the object
    prototype.Node.js >= 12.22.9, >= 14.18.3, >= 16.13.2, and >= 17.3.1 use a null protoype for the object
    these properties are being assigned to. (CVE-2022-21824)

  - A OS Command Injection vulnerability exists in Node.js versions <14.20.0, <16.20.0, <18.5.0 due to an
    insufficient IsAllowedHost check that can easily be bypassed because IsIPAddress does not properly check
    if an IP address is invalid before making DBS requests allowing rebinding attacks. (CVE-2022-32212)

  - The llhttp parser <v14.20.1, <v16.17.1 and <v18.9.1 in the http module in Node.js does not correctly parse
    and validate Transfer-Encoding headers and can lead to HTTP Request Smuggling (HRS). (CVE-2022-32213)

  - The llhttp parser <v14.20.1, <v16.17.1 and <v18.9.1 in the http module in Node.js does not strictly use
    the CRLF sequence to delimit HTTP requests. This can lead to HTTP Request Smuggling (HRS).
    (CVE-2022-32214)

  - The llhttp parser <v14.20.1, <v16.17.1 and <v18.9.1 in the http module in Node.js does not correctly
    handle multi-line Transfer-Encoding headers. This can lead to HTTP Request Smuggling (HRS).
    (CVE-2022-32215)

  - A cryptographic vulnerability exists on Node.js on linux in versions of 18.x prior to 18.40.0 which
    allowed a default path for openssl.cnf that might be accessible under some circumstances to a non-admin
    user instead of /etc/ssl as was the case in versions prior to the upgrade to OpenSSL 3. (CVE-2022-32222)

  - Node.js is vulnerable to Hijack Execution Flow: DLL Hijacking under certain conditions on Windows
    platforms.This vulnerability can be exploited if the victim has the following dependencies on a Windows
    machine:* OpenSSL has been installed and C:\Program Files\Common Files\SSL\openssl.cnf exists.Whenever
    the above conditions are present, `node.exe` will search for `providers.dll` in the current user
    directory.After that, `node.exe` will try to search for `providers.dll` by the DLL Search Order in
    Windows.It is possible for an attacker to place the malicious file `providers.dll` under a variety of
    paths and exploit this vulnerability. (CVE-2022-32223)

  - A weak randomness in WebCrypto keygen vulnerability exists in Node.js 18 due to a change with
    EntropySource() in SecretKeyGenTraits::DoKeyGen() in src/crypto/crypto_keygen.cc. There are two problems
    with this: 1) It does not check the return value, it assumes EntropySource() always succeeds, but it can
    (and sometimes will) fail. 2) The random data returned byEntropySource() may not be cryptographically
    strong and therefore not suitable as keying material. (CVE-2022-35255)

  - The llhttp parser in the http module in Node v18.7.0 does not correctly handle header fields that are not
    terminated with CLRF. This may result in HTTP Request Smuggling. (CVE-2022-35256)

  - A buffer overrun can be triggered in X.509 certificate verification, specifically in name constraint
    checking. Note that this occurs after certificate chain signature verification and requires either a CA to
    have signed the malicious certificate or for the application to continue certificate verification despite
    failure to construct a path to a trusted issuer. An attacker can craft a malicious email address to
    overflow four attacker-controlled bytes on the stack. This buffer overflow could result in a crash
    (causing a denial of service) or potentially remote code execution. Many platforms implement stack
    overflow protections which would mitigate against the risk of remote code execution. The risk may be
    further mitigated based on stack layout for any given platform/compiler. Pre-announcements of
    CVE-2022-3602 described this issue as CRITICAL. Further analysis based on some of the mitigating factors
    described above have led this to be downgraded to HIGH. Users are still encouraged to upgrade to a new
    version as soon as possible. In a TLS client, this can be triggered by connecting to a malicious server.
    In a TLS server, this can be triggered if the server requests client authentication and a malicious client
    connects. Fixed in OpenSSL 3.0.7 (Affected 3.0.0,3.0.1,3.0.2,3.0.3,3.0.4,3.0.5,3.0.6). (CVE-2022-3602)

  - A buffer overrun can be triggered in X.509 certificate verification, specifically in name constraint
    checking. Note that this occurs after certificate chain signature verification and requires either a CA to
    have signed a malicious certificate or for an application to continue certificate verification despite
    failure to construct a path to a trusted issuer. An attacker can craft a malicious email address in a
    certificate to overflow an arbitrary number of bytes containing the `.' character (decimal 46) on the
    stack. This buffer overflow could result in a crash (causing a denial of service). In a TLS client, this
    can be triggered by connecting to a malicious server. In a TLS server, this can be triggered if the server
    requests client authentication and a malicious client connects. (CVE-2022-3786)

  - A OS Command Injection vulnerability exists in Node.js versions <14.21.1, <16.18.1, <18.12.1, <19.0.1 due
    to an insufficient IsAllowedHost check that can easily be bypassed because IsIPAddress does not properly
    check if an IP address is invalid before making DBS requests allowing rebinding attacks.The fix for this
    issue in https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-32212 was incomplete and this new CVE is
    to complete the fix. (CVE-2022-43548)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/AL2023/ALAS-2023-084.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-22959.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-22960.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-43616.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-44531.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-44532.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-44533.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-21824.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-32212.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-32213.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-32214.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-32215.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-32222.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-32223.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-35255.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-35256.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-3602.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-3786.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-43548.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/faqs.html");
  script_set_attribute(attribute:"solution", value:
"Run 'dnf update nodejs --releasever=2023.0.20230222 ' to update your system.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-43616");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/10/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/02/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/03/21");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:nodejs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:nodejs-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:nodejs-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:nodejs-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:nodejs-docs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:nodejs-full-i18n");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:nodejs-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:nodejs-libs-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:npm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:v8-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux:2023");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Amazon Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (os_ver != "-2023")
{
  if (os_ver == 'A') os_ver = 'AMI';
  audit(AUDIT_OS_NOT, "Amazon Linux 2023", "Amazon Linux " + os_ver);
}

if (!get_kb_item("Host/AmazonLinux/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var pkgs = [
    {'reference':'nodejs-18.12.1-1.amzn2023.0.2', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'nodejs-18.12.1-1.amzn2023.0.2', 'cpu':'i686', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'nodejs-18.12.1-1.amzn2023.0.2', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'nodejs-debuginfo-18.12.1-1.amzn2023.0.2', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'nodejs-debuginfo-18.12.1-1.amzn2023.0.2', 'cpu':'i686', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'nodejs-debuginfo-18.12.1-1.amzn2023.0.2', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'nodejs-debugsource-18.12.1-1.amzn2023.0.2', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'nodejs-debugsource-18.12.1-1.amzn2023.0.2', 'cpu':'i686', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'nodejs-debugsource-18.12.1-1.amzn2023.0.2', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'nodejs-devel-18.12.1-1.amzn2023.0.2', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'nodejs-devel-18.12.1-1.amzn2023.0.2', 'cpu':'i686', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'nodejs-devel-18.12.1-1.amzn2023.0.2', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'nodejs-docs-18.12.1-1.amzn2023.0.2', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'nodejs-full-i18n-18.12.1-1.amzn2023.0.2', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'nodejs-full-i18n-18.12.1-1.amzn2023.0.2', 'cpu':'i686', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'nodejs-full-i18n-18.12.1-1.amzn2023.0.2', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'nodejs-libs-18.12.1-1.amzn2023.0.2', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'nodejs-libs-18.12.1-1.amzn2023.0.2', 'cpu':'i686', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'nodejs-libs-18.12.1-1.amzn2023.0.2', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'nodejs-libs-debuginfo-18.12.1-1.amzn2023.0.2', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'nodejs-libs-debuginfo-18.12.1-1.amzn2023.0.2', 'cpu':'i686', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'nodejs-libs-debuginfo-18.12.1-1.amzn2023.0.2', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'npm-8.19.2-1.18.12.1.1.amzn2023.0.2', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'npm-8.19.2-1.18.12.1.1.amzn2023.0.2', 'cpu':'i686', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'npm-8.19.2-1.18.12.1.1.amzn2023.0.2', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'v8-devel-10.2.154.15-1.18.12.1.1.amzn2023.0.2', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'v8-devel-10.2.154.15-1.18.12.1.1.amzn2023.0.2', 'cpu':'i686', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'v8-devel-10.2.154.15-1.18.12.1.1.amzn2023.0.2', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE}
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
      severity   : SECURITY_HOLE,
      extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "nodejs / nodejs-debuginfo / nodejs-debugsource / etc");
}