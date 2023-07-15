##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# AlmaLinux Security Advisory ALSA-2022:1777.
##

include('compat.inc');

if (description)
{
  script_id(161130);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/25");

  script_cve_id(
    "CVE-2021-30809",
    "CVE-2021-30818",
    "CVE-2021-30823",
    "CVE-2021-30836",
    "CVE-2021-30846",
    "CVE-2021-30848",
    "CVE-2021-30849",
    "CVE-2021-30851",
    "CVE-2021-30884",
    "CVE-2021-30887",
    "CVE-2021-30888",
    "CVE-2021-30889",
    "CVE-2021-30890",
    "CVE-2021-30897",
    "CVE-2021-30934",
    "CVE-2021-30936",
    "CVE-2021-30951",
    "CVE-2021-30952",
    "CVE-2021-30953",
    "CVE-2021-30954",
    "CVE-2021-30984",
    "CVE-2021-45481",
    "CVE-2021-45482",
    "CVE-2021-45483",
    "CVE-2022-22589",
    "CVE-2022-22590",
    "CVE-2022-22592",
    "CVE-2022-22594",
    "CVE-2022-22620",
    "CVE-2022-22637"
  );
  script_xref(name:"ALSA", value:"2022:1777");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/02/25");

  script_name(english:"AlmaLinux 8 : webkit2gtk3 (ALSA-2022:1777)");

  script_set_attribute(attribute:"synopsis", value:
"The remote AlmaLinux host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote AlmaLinux 8 host has packages installed that are affected by multiple vulnerabilities as referenced in the
ALSA-2022:1777 advisory.

  - A use after free issue was addressed with improved memory management. This issue is fixed in Safari 15,
    tvOS 15, watchOS 8, iOS 15 and iPadOS 15. Processing maliciously crafted web content may lead to arbitrary
    code execution. (CVE-2021-30809)

  - A type confusion issue was addressed with improved state handling. This issue is fixed in iOS 14.8 and
    iPadOS 14.8, tvOS 15, iOS 15 and iPadOS 15, Safari 15, watchOS 8. Processing maliciously crafted web
    content may lead to arbitrary code execution. (CVE-2021-30818)

  - A logic issue was addressed with improved restrictions. This issue is fixed in macOS Monterey 12.0.1, iOS
    14.8 and iPadOS 14.8, tvOS 15, Safari 15, watchOS 8. An attacker in a privileged network position may be
    able to bypass HSTS. (CVE-2021-30823)

  - An out-of-bounds read was addressed with improved input validation. This issue is fixed in iOS 14.8 and
    iPadOS 14.8, tvOS 15, watchOS 8, iOS 15 and iPadOS 15. Processing a maliciously crafted audio file may
    disclose restricted memory. (CVE-2021-30836)

  - A memory corruption issue was addressed with improved memory handling. This issue is fixed in iOS 14.8 and
    iPadOS 14.8, Safari 15, tvOS 15, iOS 15 and iPadOS 15, watchOS 8. Processing maliciously crafted web
    content may lead to arbitrary code execution. (CVE-2021-30846)

  - A memory corruption issue was addressed with improved memory handling. This issue is fixed in iOS 14.8 and
    iPadOS 14.8, Safari 15, iOS 15 and iPadOS 15. Processing maliciously crafted web content may lead to code
    execution. (CVE-2021-30848)

  - Multiple memory corruption issues were addressed with improved memory handling. This issue is fixed in iOS
    14.8 and iPadOS 14.8, watchOS 8, Safari 15, tvOS 15, iOS 15 and iPadOS 15, iTunes 12.12 for Windows.
    Processing maliciously crafted web content may lead to arbitrary code execution. (CVE-2021-30849)

  - A memory corruption vulnerability was addressed with improved locking. This issue is fixed in Safari 15,
    tvOS 15, watchOS 8, iOS 15 and iPadOS 15. Processing maliciously crafted web content may lead to code
    execution. (CVE-2021-30851)

  - The issue was resolved with additional restrictions on CSS compositing. This issue is fixed in tvOS 15,
    watchOS 8, iOS 15 and iPadOS 15. Visiting a maliciously crafted website may reveal a user's browsing
    history. (CVE-2021-30884)

  - A logic issue was addressed with improved restrictions. This issue is fixed in macOS Monterey 12.0.1, iOS
    15.1 and iPadOS 15.1, watchOS 8.1, tvOS 15.1. Processing maliciously crafted web content may lead to
    unexpectedly unenforced Content Security Policy. (CVE-2021-30887)

  - An information leakage issue was addressed. This issue is fixed in iOS 15.1 and iPadOS 15.1, macOS
    Monterey 12.0.1, iOS 14.8.1 and iPadOS 14.8.1, tvOS 15.1, watchOS 8.1. A malicious website using Content
    Security Policy reports may be able to leak information via redirect behavior . (CVE-2021-30888)

  - A buffer overflow issue was addressed with improved memory handling. This issue is fixed in macOS Monterey
    12.0.1, iOS 15.1 and iPadOS 15.1, watchOS 8.1, tvOS 15.1. Processing maliciously crafted web content may
    lead to arbitrary code execution. (CVE-2021-30889)

  - A logic issue was addressed with improved state management. This issue is fixed in macOS Monterey 12.0.1,
    iOS 15.1 and iPadOS 15.1, watchOS 8.1, tvOS 15.1. Processing maliciously crafted web content may lead to
    universal cross site scripting. (CVE-2021-30890)

  - An issue existed in the specification for the resource timing API. The specification was updated and the
    updated specification was implemented. This issue is fixed in macOS Monterey 12.0.1. A malicious website
    may exfiltrate data cross-origin. (CVE-2021-30897)

  - A buffer overflow issue was addressed with improved memory handling. This issue is fixed in tvOS 15.2,
    macOS Monterey 12.1, Safari 15.2, iOS 15.2 and iPadOS 15.2, watchOS 8.3. Processing maliciously crafted
    web content may lead to arbitrary code execution. (CVE-2021-30934)

  - A use after free issue was addressed with improved memory management. This issue is fixed in tvOS 15.2,
    macOS Monterey 12.1, Safari 15.2, iOS 15.2 and iPadOS 15.2, watchOS 8.3. Processing maliciously crafted
    web content may lead to arbitrary code execution. (CVE-2021-30936, CVE-2021-30951)

  - An integer overflow was addressed with improved input validation. This issue is fixed in tvOS 15.2, macOS
    Monterey 12.1, Safari 15.2, iOS 15.2 and iPadOS 15.2, watchOS 8.3. Processing maliciously crafted web
    content may lead to arbitrary code execution. (CVE-2021-30952)

  - An out-of-bounds read was addressed with improved bounds checking. This issue is fixed in tvOS 15.2, macOS
    Monterey 12.1, Safari 15.2, iOS 15.2 and iPadOS 15.2, watchOS 8.3. Processing maliciously crafted web
    content may lead to arbitrary code execution. (CVE-2021-30953)

  - A type confusion issue was addressed with improved memory handling. This issue is fixed in tvOS 15.2,
    macOS Monterey 12.1, Safari 15.2, iOS 15.2 and iPadOS 15.2, watchOS 8.3. Processing maliciously crafted
    web content may lead to arbitrary code execution. (CVE-2021-30954)

  - A race condition was addressed with improved state handling. This issue is fixed in tvOS 15.2, macOS
    Monterey 12.1, Safari 15.2, iOS 15.2 and iPadOS 15.2, watchOS 8.3. Processing maliciously crafted web
    content may lead to arbitrary code execution. (CVE-2021-30984)

  - In WebKitGTK before 2.32.4, there is incorrect memory allocation in
    WebCore::ImageBufferCairoImageSurfaceBackend::create, leading to a segmentation violation and application
    crash, a different vulnerability than CVE-2021-30889. (CVE-2021-45481)

  - In WebKitGTK before 2.32.4, there is a use-after-free in WebCore::ContainerNode::firstChild, a different
    vulnerability than CVE-2021-30889. (CVE-2021-45482)

  - In WebKitGTK before 2.32.4, there is a use-after-free in WebCore::Frame::page, a different vulnerability
    than CVE-2021-30889. (CVE-2021-45483)

  - A validation issue was addressed with improved input sanitization. This issue is fixed in iOS 15.3 and
    iPadOS 15.3, watchOS 8.4, tvOS 15.3, Safari 15.3, macOS Monterey 12.2. Processing a maliciously crafted
    mail message may lead to running arbitrary javascript. (CVE-2022-22589)

  - A use after free issue was addressed with improved memory management. This issue is fixed in iOS 15.3 and
    iPadOS 15.3, watchOS 8.4, tvOS 15.3, Safari 15.3, macOS Monterey 12.2. Processing maliciously crafted web
    content may lead to arbitrary code execution. (CVE-2022-22590)

  - A logic issue was addressed with improved state management. This issue is fixed in iOS 15.3 and iPadOS
    15.3, watchOS 8.4, tvOS 15.3, Safari 15.3, macOS Monterey 12.2. Processing maliciously crafted web content
    may prevent Content Security Policy from being enforced. (CVE-2022-22592)

  - A cross-origin issue in the IndexDB API was addressed with improved input validation. This issue is fixed
    in iOS 15.3 and iPadOS 15.3, watchOS 8.4, tvOS 15.3, Safari 15.3, macOS Monterey 12.2. A website may be
    able to track sensitive user information. (CVE-2022-22594)

  - A use after free issue was addressed with improved memory management. This issue is fixed in macOS
    Monterey 12.2.1, iOS 15.3.1 and iPadOS 15.3.1, Safari 15.3 (v. 16612.4.9.1.8 and 15612.4.9.1.8).
    Processing maliciously crafted web content may lead to arbitrary code execution. Apple is aware of a
    report that this issue may have been actively exploited.. (CVE-2022-22620)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://errata.almalinux.org/8/ALSA-2022-1777.html");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-30954");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2022-22637");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/08/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/05/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/05/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:webkit2gtk3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:webkit2gtk3-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:webkit2gtk3-jsc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:webkit2gtk3-jsc-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:alma:linux:8");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Alma Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/AlmaLinux/release", "Host/AlmaLinux/rpm-list", "Host/cpu");

  exit(0);
}


include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var release = get_kb_item('Host/AlmaLinux/release');
if (isnull(release) || 'AlmaLinux' >!< release) audit(AUDIT_OS_NOT, 'AlmaLinux');
var os_ver = pregmatch(pattern: "AlmaLinux release ([0-9]+(\.[0-9]+)?)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'AlmaLinux');
var os_ver = os_ver[1];
if (! preg(pattern:"^8([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, 'AlmaLinux 8.x', 'AlmaLinux ' + os_ver);

if (!get_kb_item('Host/AlmaLinux/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'AlmaLinux', cpu);

var pkgs = [
    {'reference':'webkit2gtk3-2.34.6-1.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'webkit2gtk3-2.34.6-1.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'webkit2gtk3-devel-2.34.6-1.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'webkit2gtk3-devel-2.34.6-1.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'webkit2gtk3-jsc-2.34.6-1.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'webkit2gtk3-jsc-2.34.6-1.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'webkit2gtk3-jsc-devel-2.34.6-1.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'webkit2gtk3-jsc-devel-2.34.6-1.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE}
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
  if (!empty_or_null(package_array['release'])) release = 'Alma-' + package_array['release'];
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'webkit2gtk3 / webkit2gtk3-devel / webkit2gtk3-jsc / etc');
}
