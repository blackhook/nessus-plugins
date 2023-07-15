#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
#
# The package checks in this plugin were extracted from
# AlmaLinux Security Advisory ALSA-2020:4451.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(157689);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/25");

  script_cve_id(
    "CVE-2019-8625",
    "CVE-2019-8710",
    "CVE-2019-8720",
    "CVE-2019-8743",
    "CVE-2019-8764",
    "CVE-2019-8766",
    "CVE-2019-8769",
    "CVE-2019-8771",
    "CVE-2019-8782",
    "CVE-2019-8783",
    "CVE-2019-8808",
    "CVE-2019-8811",
    "CVE-2019-8812",
    "CVE-2019-8813",
    "CVE-2019-8814",
    "CVE-2019-8815",
    "CVE-2019-8816",
    "CVE-2019-8819",
    "CVE-2019-8820",
    "CVE-2019-8823",
    "CVE-2019-8835",
    "CVE-2019-8844",
    "CVE-2019-8846",
    "CVE-2020-3862",
    "CVE-2020-3864",
    "CVE-2020-3865",
    "CVE-2020-3867",
    "CVE-2020-3868",
    "CVE-2020-3885",
    "CVE-2020-3894",
    "CVE-2020-3895",
    "CVE-2020-3897",
    "CVE-2020-3899",
    "CVE-2020-3900",
    "CVE-2020-3901",
    "CVE-2020-3902",
    "CVE-2020-9802",
    "CVE-2020-9803",
    "CVE-2020-9805",
    "CVE-2020-9806",
    "CVE-2020-9807",
    "CVE-2020-9843",
    "CVE-2020-9850",
    "CVE-2020-9862",
    "CVE-2020-9893",
    "CVE-2020-9894",
    "CVE-2020-9895",
    "CVE-2020-9915",
    "CVE-2020-9925",
    "CVE-2020-9952",
    "CVE-2020-10018",
    "CVE-2020-11793",
    "CVE-2020-14391",
    "CVE-2020-15503",
    "CVE-2021-30666",
    "CVE-2021-30761",
    "CVE-2021-30762"
  );
  script_xref(name:"ALSA", value:"2020:4451");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2021/11/17");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/06/13");

  script_name(english:"AlmaLinux 8 : GNOME (ALSA-2020:4451)");

  script_set_attribute(attribute:"synopsis", value:
"The remote AlmaLinux host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote AlmaLinux 8 host has packages installed that are affected by multiple vulnerabilities as referenced in the
ALSA-2020:4451 advisory.

  - A logic issue was addressed with improved state management. This issue is fixed in tvOS 13, iTunes for
    Windows 12.10.1, iCloud for Windows 10.7, iCloud for Windows 7.14. Processing maliciously crafted web
    content may lead to universal cross site scripting. (CVE-2019-8625)

  - Multiple memory corruption issues were addressed with improved memory handling. This issue is fixed in
    iCloud for Windows 11.0. Processing maliciously crafted web content may lead to arbitrary code execution.
    (CVE-2019-8710)

  - Multiple memory corruption issues were addressed with improved memory handling. This issue is fixed in
    watchOS 6.1. Processing maliciously crafted web content may lead to arbitrary code execution.
    (CVE-2019-8743)

  - A logic issue was addressed with improved state management. This issue is fixed in watchOS 6.1. Processing
    maliciously crafted web content may lead to universal cross site scripting. (CVE-2019-8764)

  - Multiple memory corruption issues were addressed with improved memory handling. This issue is fixed in
    watchOS 6.1, iCloud for Windows 11.0. Processing maliciously crafted web content may lead to arbitrary
    code execution. (CVE-2019-8766)

  - An issue existed in the drawing of web page elements. The issue was addressed with improved logic. This
    issue is fixed in iOS 13.1 and iPadOS 13.1, macOS Catalina 10.15. Visiting a maliciously crafted website
    may reveal browsing history. (CVE-2019-8769)

  - This issue was addressed with improved iframe sandbox enforcement. This issue is fixed in Safari 13.0.1,
    iOS 13. Maliciously crafted web content may violate iframe sandboxing policy. (CVE-2019-8771)

  - Multiple memory corruption issues were addressed with improved memory handling. This issue is fixed in iOS
    13.2 and iPadOS 13.2, tvOS 13.2, Safari 13.0.3, iTunes for Windows 12.10.2, iCloud for Windows 11.0.
    Processing maliciously crafted web content may lead to arbitrary code execution. (CVE-2019-8782)

  - Multiple memory corruption issues were addressed with improved memory handling. This issue is fixed in iOS
    13.2 and iPadOS 13.2, tvOS 13.2, Safari 13.0.3, iTunes for Windows 12.10.2, iCloud for Windows 11.0,
    iCloud for Windows 7.15. Processing maliciously crafted web content may lead to arbitrary code execution.
    (CVE-2019-8783, CVE-2019-8814, CVE-2019-8815, CVE-2019-8819, CVE-2019-8823)

  - Multiple memory corruption issues were addressed with improved memory handling. This issue is fixed in iOS
    13.2 and iPadOS 13.2, tvOS 13.2, watchOS 6.1, Safari 13.0.3, iTunes for Windows 12.10.2. Processing
    maliciously crafted web content may lead to arbitrary code execution. (CVE-2019-8808, CVE-2019-8812)

  - Multiple memory corruption issues were addressed with improved memory handling. This issue is fixed in iOS
    13.2 and iPadOS 13.2, tvOS 13.2, watchOS 6.1, Safari 13.0.3, iTunes for Windows 12.10.2, iCloud for
    Windows 11.0, iCloud for Windows 7.15. Processing maliciously crafted web content may lead to arbitrary
    code execution. (CVE-2019-8811, CVE-2019-8816, CVE-2019-8820)

  - A logic issue was addressed with improved state management. This issue is fixed in iOS 13.2 and iPadOS
    13.2, tvOS 13.2, Safari 13.0.3, iTunes for Windows 12.10.2, iCloud for Windows 11.0. Processing
    maliciously crafted web content may lead to universal cross site scripting. (CVE-2019-8813)

  - Multiple memory corruption issues were addressed with improved memory handling. This issue is fixed in
    tvOS 13.3, iCloud for Windows 10.9, iOS 13.3 and iPadOS 13.3, Safari 13.0.4, iTunes 12.10.3 for Windows,
    iCloud for Windows 7.16. Processing maliciously crafted web content may lead to arbitrary code execution.
    (CVE-2019-8835)

  - Multiple memory corruption issues were addressed with improved memory handling. This issue is fixed in
    tvOS 13.3, watchOS 6.1.1, iCloud for Windows 10.9, iOS 13.3 and iPadOS 13.3, Safari 13.0.4, iTunes 12.10.3
    for Windows, iCloud for Windows 7.16. Processing maliciously crafted web content may lead to arbitrary
    code execution. (CVE-2019-8844)

  - A use after free issue was addressed with improved memory management. This issue is fixed in tvOS 13.3,
    iCloud for Windows 10.9, iOS 13.3 and iPadOS 13.3, Safari 13.0.4, iTunes 12.10.3 for Windows, iCloud for
    Windows 7.16. Processing maliciously crafted web content may lead to arbitrary code execution.
    (CVE-2019-8846)

  - A denial of service issue was addressed with improved memory handling. This issue is fixed in iOS 13.3.1
    and iPadOS 13.3.1, tvOS 13.3.1, Safari 13.0.5, iTunes for Windows 12.10.4, iCloud for Windows 11.0, iCloud
    for Windows 7.17. A malicious website may be able to cause a denial of service. (CVE-2020-3862)

  - A logic issue was addressed with improved validation. This issue is fixed in iCloud for Windows 7.17,
    iTunes 12.10.4 for Windows, iCloud for Windows 10.9.2, tvOS 13.3.1, Safari 13.0.5, iOS 13.3.1 and iPadOS
    13.3.1. A DOM object context may not have had a unique security origin. (CVE-2020-3864)

  - Multiple memory corruption issues were addressed with improved memory handling. This issue is fixed in iOS
    13.3.1 and iPadOS 13.3.1, tvOS 13.3.1, Safari 13.0.5, iTunes for Windows 12.10.4, iCloud for Windows 11.0,
    iCloud for Windows 7.17. Processing maliciously crafted web content may lead to arbitrary code execution.
    (CVE-2020-3865, CVE-2020-3868)

  - A logic issue was addressed with improved state management. This issue is fixed in iOS 13.3.1 and iPadOS
    13.3.1, tvOS 13.3.1, Safari 13.0.5, iTunes for Windows 12.10.4, iCloud for Windows 11.0, iCloud for
    Windows 7.17. Processing maliciously crafted web content may lead to universal cross site scripting.
    (CVE-2020-3867)

  - A logic issue was addressed with improved restrictions. This issue is fixed in iOS 13.4 and iPadOS 13.4,
    tvOS 13.4, Safari 13.1, iTunes for Windows 12.10.5, iCloud for Windows 10.9.3, iCloud for Windows 7.18. A
    file URL may be incorrectly processed. (CVE-2020-3885)

  - A race condition was addressed with additional validation. This issue is fixed in iOS 13.4 and iPadOS
    13.4, tvOS 13.4, Safari 13.1, iTunes for Windows 12.10.5, iCloud for Windows 10.9.3, iCloud for Windows
    7.18. An application may be able to read restricted memory. (CVE-2020-3894)

  - A memory corruption issue was addressed with improved memory handling. This issue is fixed in iOS 13.4 and
    iPadOS 13.4, tvOS 13.4, watchOS 6.2, Safari 13.1, iTunes for Windows 12.10.5, iCloud for Windows 10.9.3,
    iCloud for Windows 7.18. Processing maliciously crafted web content may lead to arbitrary code execution.
    (CVE-2020-3895, CVE-2020-3900)

  - A type confusion issue was addressed with improved memory handling. This issue is fixed in iOS 13.4 and
    iPadOS 13.4, tvOS 13.4, watchOS 6.2, Safari 13.1, iTunes for Windows 12.10.5, iCloud for Windows 10.9.3,
    iCloud for Windows 7.18. A remote attacker may be able to cause arbitrary code execution. (CVE-2020-3897)

  - A memory consumption issue was addressed with improved memory handling. This issue is fixed in iOS 13.4
    and iPadOS 13.4, tvOS 13.4, watchOS 6.2, Safari 13.1, iTunes for Windows 12.10.5, iCloud for Windows
    10.9.3, iCloud for Windows 7.18. A remote attacker may be able to cause arbitrary code execution.
    (CVE-2020-3899)

  - A type confusion issue was addressed with improved memory handling. This issue is fixed in iOS 13.4 and
    iPadOS 13.4, tvOS 13.4, watchOS 6.2, Safari 13.1, iTunes for Windows 12.10.5, iCloud for Windows 10.9.3,
    iCloud for Windows 7.18. Processing maliciously crafted web content may lead to arbitrary code execution.
    (CVE-2020-3901)

  - An input validation issue was addressed with improved input validation. This issue is fixed in iOS 13.4
    and iPadOS 13.4, tvOS 13.4, Safari 13.1, iTunes for Windows 12.10.5, iCloud for Windows 10.9.3, iCloud for
    Windows 7.18. Processing maliciously crafted web content may lead to a cross site scripting attack.
    (CVE-2020-3902)

  - A logic issue was addressed with improved restrictions. This issue is fixed in iOS 13.5 and iPadOS 13.5,
    tvOS 13.4.5, watchOS 6.2.5, Safari 13.1.1, iTunes 12.10.7 for Windows, iCloud for Windows 11.2, iCloud for
    Windows 7.19. Processing maliciously crafted web content may lead to arbitrary code execution.
    (CVE-2020-9802)

  - A memory corruption issue was addressed with improved validation. This issue is fixed in iOS 13.5 and
    iPadOS 13.5, tvOS 13.4.5, watchOS 6.2.5, Safari 13.1.1, iTunes 12.10.7 for Windows, iCloud for Windows
    11.2, iCloud for Windows 7.19. Processing maliciously crafted web content may lead to arbitrary code
    execution. (CVE-2020-9803)

  - A logic issue was addressed with improved restrictions. This issue is fixed in iOS 13.5 and iPadOS 13.5,
    tvOS 13.4.5, watchOS 6.2.5, Safari 13.1.1, iTunes 12.10.7 for Windows, iCloud for Windows 11.2, iCloud for
    Windows 7.19. Processing maliciously crafted web content may lead to universal cross site scripting.
    (CVE-2020-9805)

  - A memory corruption issue was addressed with improved state management. This issue is fixed in iOS 13.5
    and iPadOS 13.5, tvOS 13.4.5, watchOS 6.2.5, Safari 13.1.1, iTunes 12.10.7 for Windows, iCloud for Windows
    11.2, iCloud for Windows 7.19. Processing maliciously crafted web content may lead to arbitrary code
    execution. (CVE-2020-9806, CVE-2020-9807)

  - An input validation issue was addressed with improved input validation. This issue is fixed in iOS 13.5
    and iPadOS 13.5, tvOS 13.4.5, watchOS 6.2.5, Safari 13.1.1, iTunes 12.10.7 for Windows, iCloud for Windows
    11.2, iCloud for Windows 7.19. Processing maliciously crafted web content may lead to a cross site
    scripting attack. (CVE-2020-9843)

  - A logic issue was addressed with improved restrictions. This issue is fixed in iOS 13.5 and iPadOS 13.5,
    tvOS 13.4.5, watchOS 6.2.5, Safari 13.1.1, iTunes 12.10.7 for Windows, iCloud for Windows 11.2, iCloud for
    Windows 7.19. A remote attacker may be able to cause arbitrary code execution. (CVE-2020-9850)

  - A command injection issue existed in Web Inspector. This issue was addressed with improved escaping. This
    issue is fixed in iOS 13.6 and iPadOS 13.6, tvOS 13.4.8, watchOS 6.2.8, Safari 13.1.2, iTunes 12.10.8 for
    Windows, iCloud for Windows 11.3, iCloud for Windows 7.20. Copying a URL from Web Inspector may lead to
    command injection. (CVE-2020-9862)

  - A use after free issue was addressed with improved memory management. This issue is fixed in iOS 13.6 and
    iPadOS 13.6, tvOS 13.4.8, watchOS 6.2.8, Safari 13.1.2, iTunes 12.10.8 for Windows, iCloud for Windows
    11.3, iCloud for Windows 7.20. A remote attacker may be able to cause unexpected application termination
    or arbitrary code execution. (CVE-2020-9893, CVE-2020-9895)

  - An out-of-bounds read was addressed with improved input validation. This issue is fixed in iOS 13.6 and
    iPadOS 13.6, tvOS 13.4.8, watchOS 6.2.8, Safari 13.1.2, iTunes 12.10.8 for Windows, iCloud for Windows
    11.3, iCloud for Windows 7.20. A remote attacker may be able to cause unexpected application termination
    or arbitrary code execution. (CVE-2020-9894)

  - An access issue existed in Content Security Policy. This issue was addressed with improved access
    restrictions. This issue is fixed in iOS 13.6 and iPadOS 13.6, tvOS 13.4.8, watchOS 6.2.8, Safari 13.1.2,
    iTunes 12.10.8 for Windows, iCloud for Windows 11.3, iCloud for Windows 7.20. Processing maliciously
    crafted web content may prevent Content Security Policy from being enforced. (CVE-2020-9915)

  - A logic issue was addressed with improved state management. This issue is fixed in iOS 13.6 and iPadOS
    13.6, tvOS 13.4.8, watchOS 6.2.8, Safari 13.1.2, iTunes 12.10.8 for Windows, iCloud for Windows 11.3,
    iCloud for Windows 7.20. Processing maliciously crafted web content may lead to universal cross site
    scripting. (CVE-2020-9925)

  - An input validation issue was addressed with improved input validation. This issue is fixed in iOS 14.0
    and iPadOS 14.0, tvOS 14.0, watchOS 7.0, Safari 14.0, iCloud for Windows 11.4, iCloud for Windows 7.21.
    Processing maliciously crafted web content may lead to a cross site scripting attack. (CVE-2020-9952)

  - WebKitGTK through 2.26.4 and WPE WebKit through 2.26.4 (which are the versions right before 2.28.0)
    contains a memory corruption issue (use-after-free) that may lead to arbitrary code execution. This issue
    has been fixed in 2.28.0 with improved memory handling. (CVE-2020-10018)

  - A use-after-free issue exists in WebKitGTK before 2.28.1 and WPE WebKit before 2.28.1 via crafted web
    content that allows remote attackers to execute arbitrary code or cause a denial of service (memory
    corruption and application crash). (CVE-2020-11793)

  - A flaw was found in the GNOME Control Center in Red Hat Enterprise Linux 8 versions prior to 8.2, where it
    improperly uses Red Hat Customer Portal credentials when a user registers a system through the GNOME
    Settings User Interface. This flaw allows a local attacker to discover the Red Hat Customer Portal
    password. The highest threat from this vulnerability is to confidentiality. (CVE-2020-14391)

  - LibRaw before 0.20-RC1 lacks a thumbnail size range check. This affects decoders/unpack_thumb.cpp,
    postprocessing/mem_image.cpp, and utils/thumb_utils.cpp. For example,
    malloc(sizeof(libraw_processed_image_t)+T.tlength) occurs without validating T.tlength. (CVE-2020-15503)

  - A buffer overflow issue was addressed with improved memory handling. This issue is fixed in iOS 12.5.3.
    Processing maliciously crafted web content may lead to arbitrary code execution. Apple is aware of a
    report that this issue may have been actively exploited.. (CVE-2021-30666)

  - A memory corruption issue was addressed with improved state management. This issue is fixed in iOS 12.5.4.
    Processing maliciously crafted web content may lead to arbitrary code execution. Apple is aware of a
    report that this issue may have been actively exploited.. (CVE-2021-30761)

  - A use after free issue was addressed with improved memory management. This issue is fixed in iOS 12.5.4.
    Processing maliciously crafted web content may lead to arbitrary code execution. Apple is aware of a
    report that this issue may have been actively exploited.. (CVE-2021-30762)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://errata.almalinux.org/8/ALSA-2020-4451.html");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-3899");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2020-9895");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Safari in Operator Side Effect Exploit');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/09/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/11/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/02/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:LibRaw-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:PackageKit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:PackageKit-command-not-found");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:PackageKit-cron");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:PackageKit-glib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:PackageKit-glib-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:PackageKit-gstreamer-plugin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:PackageKit-gtk3-module");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:dleyna-renderer");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:frei0r-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:frei0r-plugins");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:frei0r-plugins-opencv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:gnome-remote-desktop");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:gsettings-desktop-schemas");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:gtk-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:gvfs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:libsoup");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:libsoup-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:mutter-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:nautilus");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:nautilus-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:pipewire");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:pipewire-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:pipewire-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:pipewire-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:pipewire-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:pipewire0.2-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:pipewire0.2-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:potrace");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:pygobject3-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:python3-gobject");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:python3-gobject-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:tracker");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:tracker-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:vte-profile");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:vte291");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:vte291-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:webrtc-audio-processing");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:xdg-desktop-portal-gtk");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:alma:linux:8");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Alma Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
    {'reference':'dleyna-renderer-0.6.0-3.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'frei0r-devel-1.6.1-7.el8', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'frei0r-devel-1.6.1-7.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'frei0r-plugins-1.6.1-7.el8', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'frei0r-plugins-1.6.1-7.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'frei0r-plugins-opencv-1.6.1-7.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gnome-remote-desktop-0.1.8-3.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gsettings-desktop-schemas-3.32.0-5.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gtk-doc-1.28-2.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gvfs-1.36.2-10.el8', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'LibRaw-devel-0.19.5-2.el8', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'LibRaw-devel-0.19.5-2.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libsoup-2.62.3-2.el8', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libsoup-2.62.3-2.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libsoup-devel-2.62.3-2.el8', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libsoup-devel-2.62.3-2.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'mutter-devel-3.32.2-48.el8', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'mutter-devel-3.32.2-48.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'nautilus-3.28.1-14.el8', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'nautilus-devel-3.28.1-14.el8', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'nautilus-devel-3.28.1-14.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'PackageKit-1.1.12-6.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'PackageKit-command-not-found-1.1.12-6.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'PackageKit-cron-1.1.12-6.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'PackageKit-glib-1.1.12-6.el8', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'PackageKit-glib-1.1.12-6.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'PackageKit-glib-devel-1.1.12-6.el8', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'PackageKit-glib-devel-1.1.12-6.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'PackageKit-gstreamer-plugin-1.1.12-6.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'PackageKit-gtk3-module-1.1.12-6.el8', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'PackageKit-gtk3-module-1.1.12-6.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'pipewire-0.3.6-1.el8', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'pipewire-0.3.6-1.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'pipewire-devel-0.3.6-1.el8', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'pipewire-devel-0.3.6-1.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'pipewire-doc-0.3.6-1.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'pipewire-libs-0.3.6-1.el8', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'pipewire-libs-0.3.6-1.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'pipewire-utils-0.3.6-1.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'pipewire0.2-devel-0.2.7-6.el8', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'pipewire0.2-devel-0.2.7-6.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'pipewire0.2-libs-0.2.7-6.el8', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'pipewire0.2-libs-0.2.7-6.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'potrace-1.15-3.el8', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'potrace-1.15-3.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'pygobject3-devel-3.28.3-2.el8', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'pygobject3-devel-3.28.3-2.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3-gobject-3.28.3-2.el8', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3-gobject-3.28.3-2.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3-gobject-base-3.28.3-2.el8', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3-gobject-base-3.28.3-2.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'tracker-2.1.5-2.el8', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'tracker-2.1.5-2.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'tracker-devel-2.1.5-2.el8', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'tracker-devel-2.1.5-2.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'vte-profile-0.52.4-2.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'vte291-0.52.4-2.el8', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'vte291-0.52.4-2.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'vte291-devel-0.52.4-2.el8', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'vte291-devel-0.52.4-2.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'webrtc-audio-processing-0.3-9.el8', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'webrtc-audio-processing-0.3-9.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'xdg-desktop-portal-gtk-1.6.0-1.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'LibRaw-devel / PackageKit / PackageKit-command-not-found / etc');
}
