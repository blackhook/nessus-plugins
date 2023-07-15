#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# AlmaLinux Security Advisory ALSA-2022:8054.
##

include('compat.inc');

if (description)
{
  script_id(168001);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/11/19");

  script_cve_id(
    "CVE-2022-22624",
    "CVE-2022-22628",
    "CVE-2022-22629",
    "CVE-2022-22662",
    "CVE-2022-26700",
    "CVE-2022-26709",
    "CVE-2022-26710",
    "CVE-2022-26716",
    "CVE-2022-26717",
    "CVE-2022-26719",
    "CVE-2022-30293"
  );
  script_xref(name:"ALSA", value:"2022:8054");

  script_name(english:"AlmaLinux 9 : webkit2gtk3 (ALSA-2022:8054)");

  script_set_attribute(attribute:"synopsis", value:
"The remote AlmaLinux host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote AlmaLinux 9 host has packages installed that are affected by multiple vulnerabilities as referenced in the
ALSA-2022:8054 advisory.

  - A use after free issue was addressed with improved memory management. This issue is fixed in macOS
    Monterey 12.3, iOS 15.4 and iPadOS 15.4, tvOS 15.4, Safari 15.4. Processing maliciously crafted web
    content may lead to arbitrary code execution. (CVE-2022-22624)

  - A use after free issue was addressed with improved memory management. This issue is fixed in macOS
    Monterey 12.3, Safari 15.4, watchOS 8.5, iOS 15.4 and iPadOS 15.4, tvOS 15.4. Processing maliciously
    crafted web content may lead to arbitrary code execution. (CVE-2022-22628)

  - A buffer overflow issue was addressed with improved memory handling. This issue is fixed in macOS Monterey
    12.3, Safari 15.4, watchOS 8.5, iTunes 12.12.3 for Windows, iOS 15.4 and iPadOS 15.4, tvOS 15.4.
    Processing maliciously crafted web content may lead to arbitrary code execution. (CVE-2022-22629)

  - A cookie management issue was addressed with improved state management. This issue is fixed in Security
    Update 2022-003 Catalina, macOS Big Sur 11.6.5. Processing maliciously crafted web content may disclose
    sensitive user information. (CVE-2022-22662)

  - A memory corruption issue was addressed with improved state management. This issue is fixed in tvOS 15.5,
    watchOS 8.6, iOS 15.5 and iPadOS 15.5, macOS Monterey 12.4, Safari 15.5. Processing maliciously crafted
    web content may lead to code execution. (CVE-2022-26700)

  - A use after free issue was addressed with improved memory management. This issue is fixed in tvOS 15.5,
    iOS 15.5 and iPadOS 15.5, watchOS 8.6, macOS Monterey 12.4, Safari 15.5. Processing maliciously crafted
    web content may lead to arbitrary code execution. (CVE-2022-26709)

  - A use after free issue was addressed with improved memory management. This issue is fixed in iOS 15.5 and
    iPadOS 15.5, macOS Monterey 12.4, tvOS 15.5, watchOS 8.6. Processing maliciously crafted web content may
    lead to arbitrary code execution. (CVE-2022-26710)

  - A memory corruption issue was addressed with improved state management. This issue is fixed in tvOS 15.5,
    iOS 15.5 and iPadOS 15.5, watchOS 8.6, macOS Monterey 12.4, Safari 15.5. Processing maliciously crafted
    web content may lead to arbitrary code execution. (CVE-2022-26716, CVE-2022-26719)

  - A use after free issue was addressed with improved memory management. This issue is fixed in tvOS 15.5,
    watchOS 8.6, iOS 15.5 and iPadOS 15.5, macOS Monterey 12.4, Safari 15.5, iTunes 12.12.4 for Windows.
    Processing maliciously crafted web content may lead to arbitrary code execution. (CVE-2022-26717)

  - In WebKitGTK through 2.36.0 (and WPE WebKit), there is a heap-based buffer overflow in
    WebCore::TextureMapperLayer::setContentsLayer in WebCore/platform/graphics/texmap/TextureMapperLayer.cpp.
    (CVE-2022-30293)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://errata.almalinux.org/9/ALSA-2022-8054.html");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-30293");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2022-26719");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(1173, 120, 200, 416, 787);

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/03/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/11/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/11/19");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:webkit2gtk3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:webkit2gtk3-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:webkit2gtk3-jsc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:webkit2gtk3-jsc-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:alma:linux:9");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:alma:linux:9::appstream");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Alma Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
    {'reference':'webkit2gtk3-2.36.7-1.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'webkit2gtk3-devel-2.36.7-1.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'webkit2gtk3-jsc-2.36.7-1.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'webkit2gtk3-jsc-devel-2.36.7-1.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE}
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
      severity   : SECURITY_WARNING,
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
