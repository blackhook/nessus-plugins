#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux 2022 Security Advisory ALAS2022-2022-065.
##

include('compat.inc');

if (description)
{
  script_id(164745);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/05");

  script_cve_id(
    "CVE-2022-22576",
    "CVE-2022-27774",
    "CVE-2022-27775",
    "CVE-2022-27776",
    "CVE-2022-27779",
    "CVE-2022-27780",
    "CVE-2022-27782",
    "CVE-2022-30115"
  );
  script_xref(name:"IAVA", value:"2022-A-0224-S");
  script_xref(name:"CEA-ID", value:"CEA-2022-0026");

  script_name(english:"Amazon Linux 2022 :  (ALAS2022-2022-065)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Amazon Linux 2022 host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"It is, therefore, affected by multiple vulnerabilities as referenced in the ALAS2022-2022-065 advisory.

  - An improper authentication vulnerability exists in curl 7.33.0 to and including 7.82.0 which might allow
    reuse OAUTH2-authenticated connections without properly making sure that the connection was authenticated
    with the same credentials as set for this transfer. This affects SASL-enabled protocols: SMPTP(S),
    IMAP(S), POP3(S) and LDAP(S) (openldap only). (CVE-2022-22576)

  - An insufficiently protected credentials vulnerability exists in curl 4.9 to and include curl 7.82.0 are
    affected that could allow an attacker to extract credentials when follows HTTP(S) redirects is used with
    authentication could leak credentials to other services that exist on different protocols or port numbers.
    (CVE-2022-27774)

  - An information disclosure vulnerability exists in curl 7.65.0 to 7.82.0 are vulnerable that by using an
    IPv6 address that was in the connection pool but with a different zone id it could reuse a connection
    instead. (CVE-2022-27775)

  - A insufficiently protected credentials vulnerability in fixed in curl 7.83.0 might leak authentication or
    cookie header data on HTTP redirects to the same host but another port number. (CVE-2022-27776)

  - libcurl wrongly allows cookies to be set for Top Level Domains (TLDs) if thehost name is provided with a
    trailing dot.curl can be told to receive and send cookies. curl's cookie engine can bebuilt with or
    without [Public Suffix List](https://publicsuffix.org/)awareness. If PSL support not provided, a more
    rudimentary check exists to atleast prevent cookies from being set on TLDs. This check was broken if
    thehost name in the URL uses a trailing dot.This can allow arbitrary sites to set cookies that then would
    get sent to adifferent and unrelated site or domain. (CVE-2022-27779)

  - The curl URL parser wrongly accepts percent-encoded URL separators like '/'when decoding the host name
    part of a URL, making it a *different* URL usingthe wrong host name when it is later retrieved.For
    example, a URL like `http://example.com%2F127.0.0.1/`, would be allowed bythe parser and get transposed
    into `http://example.com/127.0.0.1/`. This flawcan be used to circumvent filters, checks and more.
    (CVE-2022-27780)

  - libcurl would reuse a previously created connection even when a TLS or SSHrelated option had been changed
    that should have prohibited reuse.libcurl keeps previously used connections in a connection pool for
    subsequenttransfers to reuse if one of them matches the setup. However, several TLS andSSH settings were
    left out from the configuration match checks, making themmatch too easily. (CVE-2022-27782)

  - Using its HSTS support, curl can be instructed to use HTTPS directly insteadof using an insecure clear-
    text HTTP step even when HTTP is provided in theURL. This mechanism could be bypassed if the host name in
    the given URL used atrailing dot while not using one when it built the HSTS cache. Or the otherway around
    - by having the trailing dot in the HSTS cache and *not* using thetrailing dot in the URL.
    (CVE-2022-30115)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/AL2022/ALAS-2022-065.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-22576.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-27774.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-27775.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-27776.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-27779.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-27780.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-27782.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-30115.html");
  script_set_attribute(attribute:"solution", value:
"Run 'dnf update --releasever=2022.0.20220518 curl' to update your system.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-22576");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/04/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/05/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/09/06");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:curl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:curl-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:curl-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:curl-minimal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:curl-minimal-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libcurl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libcurl-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libcurl-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libcurl-minimal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libcurl-minimal-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux:2022");
  script_set_attribute(attribute:"stig_severity", value:"II");
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
    {'reference':'curl-7.82.0-5.amzn2022', 'cpu':'aarch64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'curl-7.82.0-5.amzn2022', 'cpu':'i686', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'curl-7.82.0-5.amzn2022', 'cpu':'x86_64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'curl-debuginfo-7.82.0-5.amzn2022', 'cpu':'aarch64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'curl-debuginfo-7.82.0-5.amzn2022', 'cpu':'i686', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'curl-debuginfo-7.82.0-5.amzn2022', 'cpu':'x86_64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'curl-debugsource-7.82.0-5.amzn2022', 'cpu':'aarch64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'curl-debugsource-7.82.0-5.amzn2022', 'cpu':'i686', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'curl-debugsource-7.82.0-5.amzn2022', 'cpu':'x86_64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'curl-minimal-7.82.0-5.amzn2022', 'cpu':'aarch64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'curl-minimal-7.82.0-5.amzn2022', 'cpu':'i686', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'curl-minimal-7.82.0-5.amzn2022', 'cpu':'x86_64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'curl-minimal-debuginfo-7.82.0-5.amzn2022', 'cpu':'aarch64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'curl-minimal-debuginfo-7.82.0-5.amzn2022', 'cpu':'i686', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'curl-minimal-debuginfo-7.82.0-5.amzn2022', 'cpu':'x86_64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libcurl-7.82.0-5.amzn2022', 'cpu':'aarch64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libcurl-7.82.0-5.amzn2022', 'cpu':'i686', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libcurl-7.82.0-5.amzn2022', 'cpu':'x86_64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libcurl-debuginfo-7.82.0-5.amzn2022', 'cpu':'aarch64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libcurl-debuginfo-7.82.0-5.amzn2022', 'cpu':'i686', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libcurl-debuginfo-7.82.0-5.amzn2022', 'cpu':'x86_64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libcurl-devel-7.82.0-5.amzn2022', 'cpu':'aarch64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libcurl-devel-7.82.0-5.amzn2022', 'cpu':'i686', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libcurl-devel-7.82.0-5.amzn2022', 'cpu':'x86_64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libcurl-minimal-7.82.0-5.amzn2022', 'cpu':'aarch64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libcurl-minimal-7.82.0-5.amzn2022', 'cpu':'i686', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libcurl-minimal-7.82.0-5.amzn2022', 'cpu':'x86_64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libcurl-minimal-debuginfo-7.82.0-5.amzn2022', 'cpu':'aarch64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libcurl-minimal-debuginfo-7.82.0-5.amzn2022', 'cpu':'i686', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libcurl-minimal-debuginfo-7.82.0-5.amzn2022', 'cpu':'x86_64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE}
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
      severity   : SECURITY_WARNING,
      extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "curl / curl-debuginfo / curl-debugsource / etc");
}