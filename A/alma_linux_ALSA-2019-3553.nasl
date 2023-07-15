#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
#
# The package checks in this plugin were extracted from
# AlmaLinux Security Advisory ALSA-2019:3553.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(157524);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/25");

  script_cve_id(
    "CVE-2019-3820",
    "CVE-2019-6237",
    "CVE-2019-6251",
    "CVE-2019-8506",
    "CVE-2019-8518",
    "CVE-2019-8523",
    "CVE-2019-8524",
    "CVE-2019-8535",
    "CVE-2019-8536",
    "CVE-2019-8544",
    "CVE-2019-8551",
    "CVE-2019-8558",
    "CVE-2019-8559",
    "CVE-2019-8563",
    "CVE-2019-8571",
    "CVE-2019-8583",
    "CVE-2019-8584",
    "CVE-2019-8586",
    "CVE-2019-8587",
    "CVE-2019-8594",
    "CVE-2019-8595",
    "CVE-2019-8596",
    "CVE-2019-8597",
    "CVE-2019-8601",
    "CVE-2019-8607",
    "CVE-2019-8608",
    "CVE-2019-8609",
    "CVE-2019-8610",
    "CVE-2019-8611",
    "CVE-2019-8615",
    "CVE-2019-8619",
    "CVE-2019-8622",
    "CVE-2019-8623",
    "CVE-2019-8666",
    "CVE-2019-8671",
    "CVE-2019-8672",
    "CVE-2019-8673",
    "CVE-2019-8676",
    "CVE-2019-8677",
    "CVE-2019-8679",
    "CVE-2019-8681",
    "CVE-2019-8686",
    "CVE-2019-8687",
    "CVE-2019-8689",
    "CVE-2019-8690",
    "CVE-2019-8726",
    "CVE-2019-8735",
    "CVE-2019-8768",
    "CVE-2019-11070",
    "CVE-2019-11459",
    "CVE-2019-12795"
  );
  script_xref(name:"ALSA", value:"2019:3553");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/05/25");

  script_name(english:"AlmaLinux 8 : GNOME (ALSA-2019:3553)");

  script_set_attribute(attribute:"synopsis", value:
"The remote AlmaLinux host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote AlmaLinux 8 host has packages installed that are affected by multiple vulnerabilities as referenced in the
ALSA-2019:3553 advisory.

  - It was discovered that the gnome-shell lock screen since version 3.15.91 did not properly restrict all
    contextual actions. An attacker with physical access to a locked workstation could invoke certain keyboard
    shortcuts, and potentially other actions. (CVE-2019-3820)

  - Multiple memory corruption issues were addressed with improved memory handling. This issue is fixed in iOS
    12.3, macOS Mojave 10.14.5, tvOS 12.3, Safari 12.1.1, iTunes for Windows 12.9.5, iCloud for Windows 7.12.
    Processing maliciously crafted web content may lead to arbitrary code execution. (CVE-2019-6237,
    CVE-2019-8571, CVE-2019-8584, CVE-2019-8586, CVE-2019-8587, CVE-2019-8594, CVE-2019-8595, CVE-2019-8596,
    CVE-2019-8597, CVE-2019-8608, CVE-2019-8609, CVE-2019-8610, CVE-2019-8611, CVE-2019-8615, CVE-2019-8619)

  - WebKitGTK and WPE WebKit prior to version 2.24.1 are vulnerable to address bar spoofing upon certain
    JavaScript redirections. An attacker could cause malicious web content to be displayed as if for a trusted
    URI. This is similar to the CVE-2018-8383 issue in Microsoft Edge. (CVE-2019-6251)

  - A type confusion issue was addressed with improved memory handling. This issue is fixed in iOS 12.2, tvOS
    12.2, watchOS 5.2, Safari 12.1, iTunes 12.9.4 for Windows, iCloud for Windows 7.11. Processing maliciously
    crafted web content may lead to arbitrary code execution. (CVE-2019-8506)

  - Multiple memory corruption issues were addressed with improved memory handling. This issue is fixed in iOS
    12.2, tvOS 12.2, watchOS 5.2, Safari 12.1, iTunes 12.9.4 for Windows, iCloud for Windows 7.11. Processing
    maliciously crafted web content may lead to arbitrary code execution. (CVE-2019-8518, CVE-2019-8558,
    CVE-2019-8559, CVE-2019-8563)

  - Multiple memory corruption issues were addressed with improved memory handling. This issue is fixed in iOS
    12.2, tvOS 12.2, Safari 12.1, iTunes 12.9.4 for Windows, iCloud for Windows 7.11. Processing maliciously
    crafted web content may lead to arbitrary code execution. (CVE-2019-8523, CVE-2019-8524)

  - A memory corruption issue was addressed with improved state management. This issue is fixed in iOS 12.2,
    tvOS 12.2, Safari 12.1, iTunes 12.9.4 for Windows, iCloud for Windows 7.11. Processing maliciously crafted
    web content may lead to arbitrary code execution. (CVE-2019-8535)

  - A memory corruption issue was addressed with improved memory handling. This issue is fixed in iOS 12.2,
    tvOS 12.2, watchOS 5.2, Safari 12.1, iTunes 12.9.4 for Windows, iCloud for Windows 7.11. Processing
    maliciously crafted web content may lead to arbitrary code execution. (CVE-2019-8536, CVE-2019-8544)

  - A logic issue was addressed with improved validation. This issue is fixed in iOS 12.2, tvOS 12.2, Safari
    12.1, iTunes 12.9.4 for Windows, iCloud for Windows 7.11. Processing maliciously crafted web content may
    lead to universal cross site scripting. (CVE-2019-8551)

  - Multiple memory corruption issues were addressed with improved memory handling. This issue is fixed in iOS
    12.3, macOS Mojave 10.14.5, tvOS 12.3, watchOS 5.2.1, Safari 12.1.1, iTunes for Windows 12.9.5, iCloud for
    Windows 7.12. Processing maliciously crafted web content may lead to arbitrary code execution.
    (CVE-2019-8583, CVE-2019-8601, CVE-2019-8622, CVE-2019-8623)

  - Multiple memory corruption issues were addressed with improved memory handling. This issue is fixed in iOS
    12.4, macOS Mojave 10.14.6, tvOS 12.4, Safari 12.1.2, iTunes for Windows 12.9.6, iCloud for Windows 7.13,
    iCloud for Windows 10.6. Processing maliciously crafted web content may lead to arbitrary code execution.
    (CVE-2019-8666, CVE-2019-8671, CVE-2019-8673, CVE-2019-8677, CVE-2019-8679, CVE-2019-8681, CVE-2019-8686,
    CVE-2019-8687)

  - Multiple memory corruption issues were addressed with improved memory handling. This issue is fixed in iOS
    12.4, macOS Mojave 10.14.6, tvOS 12.4, watchOS 5.3, Safari 12.1.2, iTunes for Windows 12.9.6, iCloud for
    Windows 7.13, iCloud for Windows 10.6. Processing maliciously crafted web content may lead to arbitrary
    code execution. (CVE-2019-8672, CVE-2019-8676, CVE-2019-8689)

  - A logic issue existed in the handling of document loads. This issue was addressed with improved state
    management. This issue is fixed in iOS 12.4, macOS Mojave 10.14.6, tvOS 12.4, Safari 12.1.2, iTunes for
    Windows 12.9.6, iCloud for Windows 7.13, iCloud for Windows 10.6. Processing maliciously crafted web
    content may lead to universal cross site scripting. (CVE-2019-8690)

  - Multiple memory corruption issues were addressed with improved memory handling. This issue is fixed in
    tvOS 13, iTunes for Windows 12.10.1, iCloud for Windows 10.7, iCloud for Windows 7.14. Processing
    maliciously crafted web content may lead to arbitrary code execution. (CVE-2019-8726, CVE-2019-8735)

  - Clear History and Website Data did not clear the history. The issue was addressed with improved data
    deletion. This issue is fixed in macOS Catalina 10.15. A user may be unable to delete browsing history
    items. (CVE-2019-8768)

  - WebKitGTK and WPE WebKit prior to version 2.24.1 failed to properly apply configured HTTP proxy settings
    when downloading livestream video (HLS, DASH, or Smooth Streaming), an error resulting in deanonymization.
    This issue was corrected by changing the way livestreams are downloaded. (CVE-2019-11070)

  - The tiff_document_render() and tiff_document_get_thumbnail() functions in the TIFF document backend in
    GNOME Evince through 3.32.0 did not handle errors from TIFFReadRGBAImageOriented(), leading to
    uninitialized memory use when processing certain TIFF image files. (CVE-2019-11459)

  - daemon/gvfsdaemon.c in gvfsd from GNOME gvfs before 1.38.3, 1.40.x before 1.40.2, and 1.41.x before 1.41.3
    opened a private D-Bus server socket without configuring an authorization rule. A local attacker could
    connect to this server socket and issue D-Bus method calls. (Note that the server socket only accepts a
    single connection, so the attacker would have to discover the server and connect to the socket before its
    owner does.) (CVE-2019-12795)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://errata.almalinux.org/8/ALSA-2019-3553.html");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-8689");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2019-8735");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/01/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/11/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/02/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:gdk-pixbuf2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:gdk-pixbuf2-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:gdk-pixbuf2-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:gdk-pixbuf2-xlib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:gdk-pixbuf2-xlib-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:gnome-desktop3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:gnome-desktop3-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:libpurple");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:libpurple-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:pidgin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:pidgin-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:alma:linux:8");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Alma Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/AlmaLinux/release", "Host/AlmaLinux/rpm-list", "Host/cpu");

  exit(0);
}


include('audit.inc');
include('global_settings.inc');
include('misc_func.inc');
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
    {'reference':'gdk-pixbuf2-2.36.12-5.el8', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gdk-pixbuf2-2.36.12-5.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gdk-pixbuf2-devel-2.36.12-5.el8', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gdk-pixbuf2-devel-2.36.12-5.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gdk-pixbuf2-modules-2.36.12-5.el8', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gdk-pixbuf2-modules-2.36.12-5.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gdk-pixbuf2-xlib-2.36.12-5.el8', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gdk-pixbuf2-xlib-2.36.12-5.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gdk-pixbuf2-xlib-devel-2.36.12-5.el8', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gdk-pixbuf2-xlib-devel-2.36.12-5.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gnome-desktop3-3.32.2-1.el8', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gnome-desktop3-3.32.2-1.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gnome-desktop3-devel-3.32.2-1.el8', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gnome-desktop3-devel-3.32.2-1.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libpurple-2.13.0-5.el8', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libpurple-2.13.0-5.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libpurple-devel-2.13.0-5.el8', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libpurple-devel-2.13.0-5.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'pidgin-2.13.0-5.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'pidgin-devel-2.13.0-5.el8', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'pidgin-devel-2.13.0-5.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'gdk-pixbuf2 / gdk-pixbuf2-devel / gdk-pixbuf2-modules / etc');
}
