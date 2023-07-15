#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# AlmaLinux Security Advisory ALSA-2023:2256.
##

include('compat.inc');

if (description)
{
  script_id(175631);
  script_version("1.0");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/14");

  script_cve_id(
    "CVE-2022-32886",
    "CVE-2022-32888",
    "CVE-2022-32923",
    "CVE-2022-42799",
    "CVE-2022-42823",
    "CVE-2022-42824",
    "CVE-2022-42826",
    "CVE-2022-42852",
    "CVE-2022-42863",
    "CVE-2022-42867",
    "CVE-2022-46691",
    "CVE-2022-46692",
    "CVE-2022-46698",
    "CVE-2022-46699",
    "CVE-2022-46700",
    "CVE-2023-23517",
    "CVE-2023-23518",
    "CVE-2023-25358",
    "CVE-2023-25360",
    "CVE-2023-25361",
    "CVE-2023-25362",
    "CVE-2023-25363"
  );
  script_xref(name:"ALSA", value:"2023:2256");

  script_name(english:"AlmaLinux 9 : webkit2gtk3 (ALSA-2023:2256)");

  script_set_attribute(attribute:"synopsis", value:
"The remote AlmaLinux host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote AlmaLinux 9 host has packages installed that are affected by multiple vulnerabilities as referenced in the
ALSA-2023:2256 advisory.

  - A buffer overflow issue was addressed with improved memory handling. This issue is fixed in Safari 16, iOS
    16, iOS 15.7 and iPadOS 15.7. Processing maliciously crafted web content may lead to arbitrary code
    execution. (CVE-2022-32886)

  - An out-of-bounds write issue was addressed with improved bounds checking. This issue is fixed in macOS Big
    Sur 11.7, macOS Ventura 13, iOS 16, iOS 15.7 and iPadOS 15.7, watchOS 9, macOS Monterey 12.6, tvOS 16.
    Processing maliciously crafted web content may lead to arbitrary code execution. (CVE-2022-32888)

  - A correctness issue in the JIT was addressed with improved checks. This issue is fixed in tvOS 16.1, iOS
    15.7.1 and iPadOS 15.7.1, macOS Ventura 13, watchOS 9.1, Safari 16.1, iOS 16.1 and iPadOS 16. Processing
    maliciously crafted web content may disclose internal states of the app. (CVE-2022-32923)

  - The issue was addressed with improved UI handling. This issue is fixed in tvOS 16.1, macOS Ventura 13,
    watchOS 9.1, Safari 16.1, iOS 16.1 and iPadOS 16. Visiting a malicious website may lead to user interface
    spoofing. (CVE-2022-42799)

  - A type confusion issue was addressed with improved memory handling. This issue is fixed in tvOS 16.1,
    macOS Ventura 13, watchOS 9.1, Safari 16.1, iOS 16.1 and iPadOS 16. Processing maliciously crafted web
    content may lead to arbitrary code execution. (CVE-2022-42823)

  - A logic issue was addressed with improved state management. This issue is fixed in tvOS 16.1, macOS
    Ventura 13, watchOS 9.1, Safari 16.1, iOS 16.1 and iPadOS 16. Processing maliciously crafted web content
    may disclose sensitive user information. (CVE-2022-42824)

  - A use after free issue was addressed with improved memory management. This issue is fixed in macOS Ventura
    13, iOS 16.1 and iPadOS 16, Safari 16.1. Processing maliciously crafted web content may lead to arbitrary
    code execution. (CVE-2022-42826)

  - The issue was addressed with improved memory handling. This issue is fixed in Safari 16.2, tvOS 16.2,
    macOS Ventura 13.1, iOS 15.7.2 and iPadOS 15.7.2, iOS 16.2 and iPadOS 16.2, watchOS 9.2. Processing
    maliciously crafted web content may result in the disclosure of process memory. (CVE-2022-42852)

  - A memory corruption issue was addressed with improved state management. This issue is fixed in Safari
    16.2, tvOS 16.2, macOS Ventura 13.1, iOS 16.2 and iPadOS 16.2, watchOS 9.2. Processing maliciously crafted
    web content may lead to arbitrary code execution. (CVE-2022-42863, CVE-2022-46699)

  - A use after free issue was addressed with improved memory management. This issue is fixed in Safari 16.2,
    tvOS 16.2, macOS Ventura 13.1, iOS 16.2 and iPadOS 16.2, watchOS 9.2. Processing maliciously crafted web
    content may lead to arbitrary code execution. (CVE-2022-42867)

  - A memory consumption issue was addressed with improved memory handling. This issue is fixed in Safari
    16.2, tvOS 16.2, macOS Ventura 13.1, iOS 15.7.2 and iPadOS 15.7.2, iOS 16.2 and iPadOS 16.2, watchOS 9.2.
    Processing maliciously crafted web content may lead to arbitrary code execution. (CVE-2022-46691)

  - A logic issue was addressed with improved state management. This issue is fixed in Safari 16.2, tvOS 16.2,
    iCloud for Windows 14.1, iOS 15.7.2 and iPadOS 15.7.2, macOS Ventura 13.1, iOS 16.2 and iPadOS 16.2,
    watchOS 9.2. Processing maliciously crafted web content may bypass Same Origin Policy. (CVE-2022-46692)

  - A logic issue was addressed with improved checks. This issue is fixed in Safari 16.2, tvOS 16.2, iCloud
    for Windows 14.1, macOS Ventura 13.1, iOS 16.2 and iPadOS 16.2, watchOS 9.2. Processing maliciously
    crafted web content may disclose sensitive user information. (CVE-2022-46698)

  - A memory corruption issue was addressed with improved input validation. This issue is fixed in Safari
    16.2, tvOS 16.2, macOS Ventura 13.1, iOS 15.7.2 and iPadOS 15.7.2, iOS 16.2 and iPadOS 16.2, watchOS 9.2.
    Processing maliciously crafted web content may lead to arbitrary code execution. (CVE-2022-46700)

  - The issue was addressed with improved memory handling. This issue is fixed in macOS Ventura 13.2, macOS
    Monterey 12.6.3, tvOS 16.3, Safari 16.3, watchOS 9.3, iOS 16.3 and iPadOS 16.3, macOS Big Sur 11.7.3.
    Processing maliciously crafted web content may lead to arbitrary code execution. (CVE-2023-23517,
    CVE-2023-23518)

  - A use-after-free vulnerability in WebCore::RenderLayer::addChild in WebKitGTK before 2.36.8 allows
    attackers to execute code remotely. (CVE-2023-25358)

  - A use-after-free vulnerability in WebCore::RenderLayer::renderer in WebKitGTK before 2.36.8 allows
    attackers to execute code remotely. (CVE-2023-25360)

  - A use-after-free vulnerability in WebCore::RenderLayer::setNextSibling in WebKitGTK before 2.36.8 allows
    attackers to execute code remotely. (CVE-2023-25361)

  - A use-after-free vulnerability in WebCore::RenderLayer::repaintBlockSelectionGaps in WebKitGTK before
    2.36.8 allows attackers to execute code remotely. (CVE-2023-25362)

  - A use-after-free vulnerability in WebCore::RenderLayer::updateDescendantDependentFlags in WebKitGTK before
    2.36.8 allows attackers to execute code remotely. (CVE-2023-25363)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://errata.almalinux.org/9/ALSA-2023-2256.html");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-25363");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(1021, 119, 200, 416, 787, 843, 94);

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/09/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/05/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/05/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:webkit2gtk3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:webkit2gtk3-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:webkit2gtk3-jsc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:webkit2gtk3-jsc-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:alma:linux:9");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:alma:linux:9::appstream");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:alma:linux:9::baseos");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:alma:linux:9::crb");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:alma:linux:9::highavailability");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:alma:linux:9::nfv");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:alma:linux:9::realtime");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:alma:linux:9::resilientstorage");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:alma:linux:9::sap");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:alma:linux:9::sap_hana");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:alma:linux:9::supplementary");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Alma Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/AlmaLinux/release", "Host/AlmaLinux/rpm-list", "Host/cpu");

  exit(0);
}


include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item('Host/AlmaLinux/release');
if (isnull(os_release) || 'AlmaLinux' >!< os_release) audit(AUDIT_OS_NOT, 'AlmaLinux');
var os_ver = pregmatch(pattern: "AlmaLinux release ([0-9]+(\.[0-9]+)?)", string:os_release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'AlmaLinux');
os_ver = os_ver[1];
if (! preg(pattern:"^9([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, 'AlmaLinux 9.x', 'AlmaLinux ' + os_ver);

if (!get_kb_item('Host/AlmaLinux/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'AlmaLinux', cpu);

var pkgs = [
    {'reference':'webkit2gtk3-2.38.5-1.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'webkit2gtk3-devel-2.38.5-1.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'webkit2gtk3-jsc-2.38.5-1.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'webkit2gtk3-jsc-devel-2.38.5-1.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE}
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
  if (!empty_or_null(package_array['release'])) _release = 'Alma-' + package_array['release'];
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'webkit2gtk3 / webkit2gtk3-devel / webkit2gtk3-jsc / etc');
}
