##
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Oracle Linux Security Advisory ELSA-2020-4451.
##

include('compat.inc');

if (description)
{
  script_id(142763);
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
    "CVE-2020-10018",
    "CVE-2020-11793",
    "CVE-2020-14391",
    "CVE-2020-15503"
  );
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/06/13");

  script_name(english:"Oracle Linux 8 : GNOME (ELSA-2020-4451)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Oracle Linux host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Oracle Linux 8 host has packages installed that are affected by multiple vulnerabilities as referenced in the
ELSA-2020-4451 advisory.

  - webkitgtk: Multiple memory corruption issues leading to arbitrary code execution (CVE-2019-8720)

  - Multiple memory corruption issues were addressed with improved memory handling. This issue is fixed in
    watchOS 6.1, iCloud for Windows 11.0. Processing maliciously crafted web content may lead to arbitrary
    code execution. (CVE-2019-8766)

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

  - Multiple memory corruption issues were addressed with improved memory handling. This issue is fixed in iOS
    13.2 and iPadOS 13.2, tvOS 13.2, watchOS 6.1, Safari 13.0.3, iTunes for Windows 12.10.2. Processing
    maliciously crafted web content may lead to arbitrary code execution. (CVE-2019-8808, CVE-2019-8812)

  - A logic issue was addressed with improved state management. This issue is fixed in iOS 13.2 and iPadOS
    13.2, tvOS 13.2, Safari 13.0.3, iTunes for Windows 12.10.2, iCloud for Windows 11.0. Processing
    maliciously crafted web content may lead to universal cross site scripting. (CVE-2019-8813)

  - Multiple memory corruption issues were addressed with improved memory handling. This issue is fixed in iOS
    13.2 and iPadOS 13.2, tvOS 13.2, Safari 13.0.3, iTunes for Windows 12.10.2, iCloud for Windows 11.0,
    iCloud for Windows 7.15. Processing maliciously crafted web content may lead to arbitrary code execution.
    (CVE-2019-8783, CVE-2019-8814, CVE-2019-8815, CVE-2019-8819, CVE-2019-8823)

  - An issue existed in the drawing of web page elements. The issue was addressed with improved logic. This
    issue is fixed in iOS 13.1 and iPadOS 13.1, macOS Catalina 10.15. Visiting a maliciously crafted website
    may reveal browsing history. (CVE-2019-8769)

  - This issue was addressed with improved iframe sandbox enforcement. This issue is fixed in Safari 13.0.1,
    iOS 13. Maliciously crafted web content may violate iframe sandboxing policy. (CVE-2019-8771)

  - Multiple memory corruption issues were addressed with improved memory handling. This issue is fixed in iOS
    13.2 and iPadOS 13.2, tvOS 13.2, Safari 13.0.3, iTunes for Windows 12.10.2, iCloud for Windows 11.0.
    Processing maliciously crafted web content may lead to arbitrary code execution. (CVE-2019-8782)

  - Multiple memory corruption issues were addressed with improved memory handling. This issue is fixed in iOS
    13.2 and iPadOS 13.2, tvOS 13.2, watchOS 6.1, Safari 13.0.3, iTunes for Windows 12.10.2, iCloud for
    Windows 11.0, iCloud for Windows 7.15. Processing maliciously crafted web content may lead to arbitrary
    code execution. (CVE-2019-8811, CVE-2019-8816, CVE-2019-8820)

  - A logic issue was addressed with improved validation. This issue is fixed in iCloud for Windows 7.17,
    iTunes 12.10.4 for Windows, iCloud for Windows 10.9.2, tvOS 13.3.1, Safari 13.0.5, iOS 13.3.1 and iPadOS
    13.3.1. A DOM object context may not have had a unique security origin. (CVE-2020-3864)

  - Multiple memory corruption issues were addressed with improved memory handling. This issue is fixed in iOS
    13.3.1 and iPadOS 13.3.1, tvOS 13.3.1, Safari 13.0.5, iTunes for Windows 12.10.4, iCloud for Windows 11.0,
    iCloud for Windows 7.17. Processing maliciously crafted web content may lead to arbitrary code execution.
    (CVE-2020-3865, CVE-2020-3868)

  - A logic issue was addressed with improved restrictions. This issue is fixed in iOS 13.4 and iPadOS 13.4,
    tvOS 13.4, Safari 13.1, iTunes for Windows 12.10.5, iCloud for Windows 10.9.3, iCloud for Windows 7.18. A
    file URL may be incorrectly processed. (CVE-2020-3885)

  - A race condition was addressed with additional validation. This issue is fixed in iOS 13.4 and iPadOS
    13.4, tvOS 13.4, Safari 13.1, iTunes for Windows 12.10.5, iCloud for Windows 10.9.3, iCloud for Windows
    7.18. An application may be able to read restricted memory. (CVE-2020-3894)

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

  - A logic issue was addressed with improved state management. This issue is fixed in iOS 13.3.1 and iPadOS
    13.3.1, tvOS 13.3.1, Safari 13.0.5, iTunes for Windows 12.10.4, iCloud for Windows 11.0, iCloud for
    Windows 7.17. Processing maliciously crafted web content may lead to universal cross site scripting.
    (CVE-2020-3867)

  - A memory corruption issue was addressed with improved memory handling. This issue is fixed in iOS 13.4 and
    iPadOS 13.4, tvOS 13.4, watchOS 6.2, Safari 13.1, iTunes for Windows 12.10.5, iCloud for Windows 10.9.3,
    iCloud for Windows 7.18. Processing maliciously crafted web content may lead to arbitrary code execution.
    (CVE-2020-3895, CVE-2020-3900)

  - A use-after-free issue exists in WebKitGTK before 2.28.1 and WPE WebKit before 2.28.1 via crafted web
    content that allows remote attackers to execute arbitrary code or cause a denial of service (memory
    corruption and application crash). (CVE-2020-11793)

  - WebKitGTK through 2.26.4 and WPE WebKit through 2.26.4 (which are the versions right before 2.28.0)
    contains a memory corruption issue (use-after-free) that may lead to arbitrary code execution. This issue
    has been fixed in 2.28.0 with improved memory handling. (CVE-2020-10018)

  - A memory corruption issue was addressed with improved state management. This issue is fixed in iOS 13.5
    and iPadOS 13.5, tvOS 13.4.5, watchOS 6.2.5, Safari 13.1.1, iTunes 12.10.7 for Windows, iCloud for Windows
    11.2, iCloud for Windows 7.19. Processing maliciously crafted web content may lead to arbitrary code
    execution. (CVE-2020-9806, CVE-2020-9807)

  - A logic issue was addressed with improved restrictions. This issue is fixed in iOS 13.5 and iPadOS 13.5,
    tvOS 13.4.5, watchOS 6.2.5, Safari 13.1.1, iTunes 12.10.7 for Windows, iCloud for Windows 11.2, iCloud for
    Windows 7.19. A remote attacker may be able to cause arbitrary code execution. (CVE-2020-9850)

  - An out-of-bounds read was addressed with improved input validation. This issue is fixed in iOS 13.6 and
    iPadOS 13.6, tvOS 13.4.8, watchOS 6.2.8, Safari 13.1.2, iTunes 12.10.8 for Windows, iCloud for Windows
    11.3, iCloud for Windows 7.20. A remote attacker may be able to cause unexpected application termination
    or arbitrary code execution. (CVE-2020-9894)

  - A use after free issue was addressed with improved memory management. This issue is fixed in iOS 13.6 and
    iPadOS 13.6, tvOS 13.4.8, watchOS 6.2.8, Safari 13.1.2, iTunes 12.10.8 for Windows, iCloud for Windows
    11.3, iCloud for Windows 7.20. A remote attacker may be able to cause unexpected application termination
    or arbitrary code execution. (CVE-2020-9893, CVE-2020-9895)

  - An access issue existed in Content Security Policy. This issue was addressed with improved access
    restrictions. This issue is fixed in iOS 13.6 and iPadOS 13.6, tvOS 13.4.8, watchOS 6.2.8, Safari 13.1.2,
    iTunes 12.10.8 for Windows, iCloud for Windows 11.3, iCloud for Windows 7.20. Processing maliciously
    crafted web content may prevent Content Security Policy from being enforced. (CVE-2020-9915)

  - gnome-settings-daemon: Red Hat Customer Portal password logged and passed as command line argument when
    user registers through GNOME control center (CVE-2020-14391)

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

  - An input validation issue was addressed with improved input validation. This issue is fixed in iOS 13.5
    and iPadOS 13.5, tvOS 13.4.5, watchOS 6.2.5, Safari 13.1.1, iTunes 12.10.7 for Windows, iCloud for Windows
    11.2, iCloud for Windows 7.19. Processing maliciously crafted web content may lead to a cross site
    scripting attack. (CVE-2020-9843)

  - A command injection issue existed in Web Inspector. This issue was addressed with improved escaping. This
    issue is fixed in iOS 13.6 and iPadOS 13.6, tvOS 13.4.8, watchOS 6.2.8, Safari 13.1.2, iTunes 12.10.8 for
    Windows, iCloud for Windows 11.3, iCloud for Windows 7.20. Copying a URL from Web Inspector may lead to
    command injection. (CVE-2020-9862)

  - A logic issue was addressed with improved state management. This issue is fixed in iOS 13.6 and iPadOS
    13.6, tvOS 13.4.8, watchOS 6.2.8, Safari 13.1.2, iTunes 12.10.8 for Windows, iCloud for Windows 11.3,
    iCloud for Windows 7.20. Processing maliciously crafted web content may lead to universal cross site
    scripting. (CVE-2020-9925)

  - LibRaw before 0.20-RC1 lacks a thumbnail size range check. This affects decoders/unpack_thumb.cpp,
    postprocessing/mem_image.cpp, and utils/thumb_utils.cpp. For example,
    malloc(sizeof(libraw_processed_image_t)+T.tlength) occurs without validating T.tlength. (CVE-2020-15503)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://linux.oracle.com/errata/ELSA-2020-4451.html");
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
  script_set_attribute(attribute:"patch_publication_date", value:"2020/11/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/11/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:LibRaw");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:LibRaw-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:PackageKit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:PackageKit-command-not-found");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:PackageKit-cron");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:PackageKit-glib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:PackageKit-glib-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:PackageKit-gstreamer-plugin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:PackageKit-gtk3-module");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:dleyna-renderer");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:frei0r-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:frei0r-plugins");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:frei0r-plugins-opencv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:gdm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:gnome-classic-session");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:gnome-control-center");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:gnome-control-center-filesystem");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:gnome-photos");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:gnome-photos-tests");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:gnome-remote-desktop");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:gnome-session");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:gnome-session-wayland-session");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:gnome-session-xsession");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:gnome-settings-daemon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:gnome-shell");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:gnome-shell-extension-apps-menu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:gnome-shell-extension-auto-move-windows");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:gnome-shell-extension-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:gnome-shell-extension-dash-to-dock");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:gnome-shell-extension-desktop-icons");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:gnome-shell-extension-disable-screenshield");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:gnome-shell-extension-drive-menu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:gnome-shell-extension-horizontal-workspaces");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:gnome-shell-extension-launch-new-instance");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:gnome-shell-extension-native-window-placement");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:gnome-shell-extension-no-hot-corner");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:gnome-shell-extension-panel-favorites");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:gnome-shell-extension-places-menu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:gnome-shell-extension-screenshot-window-sizer");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:gnome-shell-extension-systemMonitor");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:gnome-shell-extension-top-icons");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:gnome-shell-extension-updates-dialog");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:gnome-shell-extension-user-theme");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:gnome-shell-extension-window-grouper");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:gnome-shell-extension-window-list");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:gnome-shell-extension-windowsNavigator");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:gnome-shell-extension-workspace-indicator");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:gnome-terminal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:gnome-terminal-nautilus");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:gsettings-desktop-schemas");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:gsettings-desktop-schemas-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:gtk-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:gtk-update-icon-cache");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:gtk3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:gtk3-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:gtk3-immodule-xim");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:gvfs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:gvfs-afc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:gvfs-afp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:gvfs-archive");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:gvfs-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:gvfs-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:gvfs-fuse");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:gvfs-goa");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:gvfs-gphoto2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:gvfs-mtp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:gvfs-smb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libsoup");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libsoup-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:mutter");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:mutter-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:nautilus");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:nautilus-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:nautilus-extensions");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:pipewire");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:pipewire-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:pipewire-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:pipewire-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:pipewire-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:pipewire0.2-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:pipewire0.2-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:potrace");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:pygobject3-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python3-gobject");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python3-gobject-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:tracker");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:tracker-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:vte-profile");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:vte291");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:vte291-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:webkit2gtk3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:webkit2gtk3-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:webkit2gtk3-jsc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:webkit2gtk3-jsc-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:webrtc-audio-processing");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:xdg-desktop-portal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:xdg-desktop-portal-gtk");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Oracle Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2020-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/OracleLinux", "Host/RedHat/release", "Host/RedHat/rpm-list", "Host/local_checks_enabled");

  exit(0);
}


include('audit.inc');
include('global_settings.inc');
include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item('Host/OracleLinux')) audit(AUDIT_OS_NOT, 'Oracle Linux');
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || !pregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux)", string:release)) audit(AUDIT_OS_NOT, 'Oracle Linux');
os_ver = pregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux) .*release ([0-9]+(\.[0-9]+)?)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'Oracle Linux');
os_ver = os_ver[1];
if (! preg(pattern:"^8([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, 'Oracle Linux 8', 'Oracle Linux ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Oracle Linux', cpu);

pkgs = [
    {'reference':'dleyna-renderer-0.6.0-3.el8', 'cpu':'x86_64', 'release':'8'},
    {'reference':'frei0r-devel-1.6.1-7.el8', 'cpu':'aarch64', 'release':'8'},
    {'reference':'frei0r-devel-1.6.1-7.el8', 'cpu':'i686', 'release':'8'},
    {'reference':'frei0r-devel-1.6.1-7.el8', 'cpu':'x86_64', 'release':'8'},
    {'reference':'frei0r-plugins-1.6.1-7.el8', 'cpu':'aarch64', 'release':'8'},
    {'reference':'frei0r-plugins-1.6.1-7.el8', 'cpu':'i686', 'release':'8'},
    {'reference':'frei0r-plugins-1.6.1-7.el8', 'cpu':'x86_64', 'release':'8'},
    {'reference':'frei0r-plugins-opencv-1.6.1-7.el8', 'cpu':'aarch64', 'release':'8'},
    {'reference':'frei0r-plugins-opencv-1.6.1-7.el8', 'cpu':'x86_64', 'release':'8'},
    {'reference':'gdm-3.28.3-34.el8', 'cpu':'aarch64', 'release':'8', 'epoch':'1'},
    {'reference':'gdm-3.28.3-34.el8', 'cpu':'i686', 'release':'8', 'epoch':'1'},
    {'reference':'gdm-3.28.3-34.el8', 'cpu':'x86_64', 'release':'8', 'epoch':'1'},
    {'reference':'gnome-classic-session-3.32.1-11.el8', 'release':'8'},
    {'reference':'gnome-control-center-3.28.2-22.el8', 'cpu':'aarch64', 'release':'8'},
    {'reference':'gnome-control-center-3.28.2-22.el8', 'cpu':'x86_64', 'release':'8'},
    {'reference':'gnome-control-center-filesystem-3.28.2-22.el8', 'release':'8'},
    {'reference':'gnome-photos-3.28.1-3.el8', 'cpu':'x86_64', 'release':'8'},
    {'reference':'gnome-photos-tests-3.28.1-3.el8', 'cpu':'x86_64', 'release':'8'},
    {'reference':'gnome-remote-desktop-0.1.8-3.el8', 'cpu':'aarch64', 'release':'8'},
    {'reference':'gnome-remote-desktop-0.1.8-3.el8', 'cpu':'x86_64', 'release':'8'},
    {'reference':'gnome-session-3.28.1-10.0.1.el8', 'cpu':'aarch64', 'release':'8'},
    {'reference':'gnome-session-3.28.1-10.0.1.el8', 'cpu':'x86_64', 'release':'8'},
    {'reference':'gnome-session-wayland-session-3.28.1-10.0.1.el8', 'cpu':'aarch64', 'release':'8'},
    {'reference':'gnome-session-wayland-session-3.28.1-10.0.1.el8', 'cpu':'x86_64', 'release':'8'},
    {'reference':'gnome-session-xsession-3.28.1-10.0.1.el8', 'cpu':'aarch64', 'release':'8'},
    {'reference':'gnome-session-xsession-3.28.1-10.0.1.el8', 'cpu':'x86_64', 'release':'8'},
    {'reference':'gnome-settings-daemon-3.32.0-11.el8', 'cpu':'aarch64', 'release':'8'},
    {'reference':'gnome-settings-daemon-3.32.0-11.el8', 'cpu':'x86_64', 'release':'8'},
    {'reference':'gnome-shell-3.32.2-20.el8', 'cpu':'aarch64', 'release':'8'},
    {'reference':'gnome-shell-3.32.2-20.el8', 'cpu':'x86_64', 'release':'8'},
    {'reference':'gnome-shell-extension-apps-menu-3.32.1-11.el8', 'release':'8'},
    {'reference':'gnome-shell-extension-auto-move-windows-3.32.1-11.el8', 'release':'8'},
    {'reference':'gnome-shell-extension-common-3.32.1-11.el8', 'release':'8'},
    {'reference':'gnome-shell-extension-dash-to-dock-3.32.1-11.el8', 'release':'8'},
    {'reference':'gnome-shell-extension-desktop-icons-3.32.1-11.el8', 'release':'8'},
    {'reference':'gnome-shell-extension-disable-screenshield-3.32.1-11.el8', 'release':'8'},
    {'reference':'gnome-shell-extension-drive-menu-3.32.1-11.el8', 'release':'8'},
    {'reference':'gnome-shell-extension-horizontal-workspaces-3.32.1-11.el8', 'release':'8'},
    {'reference':'gnome-shell-extension-launch-new-instance-3.32.1-11.el8', 'release':'8'},
    {'reference':'gnome-shell-extension-native-window-placement-3.32.1-11.el8', 'release':'8'},
    {'reference':'gnome-shell-extension-no-hot-corner-3.32.1-11.el8', 'release':'8'},
    {'reference':'gnome-shell-extension-panel-favorites-3.32.1-11.el8', 'release':'8'},
    {'reference':'gnome-shell-extension-places-menu-3.32.1-11.el8', 'release':'8'},
    {'reference':'gnome-shell-extension-screenshot-window-sizer-3.32.1-11.el8', 'release':'8'},
    {'reference':'gnome-shell-extension-systemMonitor-3.32.1-11.el8', 'release':'8'},
    {'reference':'gnome-shell-extension-top-icons-3.32.1-11.el8', 'release':'8'},
    {'reference':'gnome-shell-extension-updates-dialog-3.32.1-11.el8', 'release':'8'},
    {'reference':'gnome-shell-extension-user-theme-3.32.1-11.el8', 'release':'8'},
    {'reference':'gnome-shell-extension-window-grouper-3.32.1-11.el8', 'release':'8'},
    {'reference':'gnome-shell-extension-window-list-3.32.1-11.el8', 'release':'8'},
    {'reference':'gnome-shell-extension-windowsNavigator-3.32.1-11.el8', 'release':'8'},
    {'reference':'gnome-shell-extension-workspace-indicator-3.32.1-11.el8', 'release':'8'},
    {'reference':'gnome-terminal-3.28.3-2.el8', 'cpu':'aarch64', 'release':'8'},
    {'reference':'gnome-terminal-3.28.3-2.el8', 'cpu':'x86_64', 'release':'8'},
    {'reference':'gnome-terminal-nautilus-3.28.3-2.el8', 'cpu':'aarch64', 'release':'8'},
    {'reference':'gnome-terminal-nautilus-3.28.3-2.el8', 'cpu':'x86_64', 'release':'8'},
    {'reference':'gsettings-desktop-schemas-3.32.0-5.el8', 'cpu':'aarch64', 'release':'8'},
    {'reference':'gsettings-desktop-schemas-3.32.0-5.el8', 'cpu':'i686', 'release':'8'},
    {'reference':'gsettings-desktop-schemas-3.32.0-5.el8', 'cpu':'x86_64', 'release':'8'},
    {'reference':'gsettings-desktop-schemas-devel-3.32.0-5.el8', 'cpu':'aarch64', 'release':'8'},
    {'reference':'gsettings-desktop-schemas-devel-3.32.0-5.el8', 'cpu':'i686', 'release':'8'},
    {'reference':'gsettings-desktop-schemas-devel-3.32.0-5.el8', 'cpu':'x86_64', 'release':'8'},
    {'reference':'gtk-doc-1.28-2.el8', 'cpu':'aarch64', 'release':'8'},
    {'reference':'gtk-doc-1.28-2.el8', 'cpu':'x86_64', 'release':'8'},
    {'reference':'gtk-update-icon-cache-3.22.30-6.el8', 'cpu':'aarch64', 'release':'8'},
    {'reference':'gtk-update-icon-cache-3.22.30-6.el8', 'cpu':'x86_64', 'release':'8'},
    {'reference':'gtk3-3.22.30-6.el8', 'cpu':'aarch64', 'release':'8'},
    {'reference':'gtk3-3.22.30-6.el8', 'cpu':'i686', 'release':'8'},
    {'reference':'gtk3-3.22.30-6.el8', 'cpu':'x86_64', 'release':'8'},
    {'reference':'gtk3-devel-3.22.30-6.el8', 'cpu':'aarch64', 'release':'8'},
    {'reference':'gtk3-devel-3.22.30-6.el8', 'cpu':'i686', 'release':'8'},
    {'reference':'gtk3-devel-3.22.30-6.el8', 'cpu':'x86_64', 'release':'8'},
    {'reference':'gtk3-immodule-xim-3.22.30-6.el8', 'cpu':'aarch64', 'release':'8'},
    {'reference':'gtk3-immodule-xim-3.22.30-6.el8', 'cpu':'x86_64', 'release':'8'},
    {'reference':'gvfs-1.36.2-10.el8', 'cpu':'aarch64', 'release':'8'},
    {'reference':'gvfs-1.36.2-10.el8', 'cpu':'i686', 'release':'8'},
    {'reference':'gvfs-1.36.2-10.el8', 'cpu':'x86_64', 'release':'8'},
    {'reference':'gvfs-afc-1.36.2-10.el8', 'cpu':'aarch64', 'release':'8'},
    {'reference':'gvfs-afc-1.36.2-10.el8', 'cpu':'x86_64', 'release':'8'},
    {'reference':'gvfs-afp-1.36.2-10.el8', 'cpu':'aarch64', 'release':'8'},
    {'reference':'gvfs-afp-1.36.2-10.el8', 'cpu':'x86_64', 'release':'8'},
    {'reference':'gvfs-archive-1.36.2-10.el8', 'cpu':'aarch64', 'release':'8'},
    {'reference':'gvfs-archive-1.36.2-10.el8', 'cpu':'x86_64', 'release':'8'},
    {'reference':'gvfs-client-1.36.2-10.el8', 'cpu':'aarch64', 'release':'8'},
    {'reference':'gvfs-client-1.36.2-10.el8', 'cpu':'i686', 'release':'8'},
    {'reference':'gvfs-client-1.36.2-10.el8', 'cpu':'x86_64', 'release':'8'},
    {'reference':'gvfs-devel-1.36.2-10.el8', 'cpu':'aarch64', 'release':'8'},
    {'reference':'gvfs-devel-1.36.2-10.el8', 'cpu':'i686', 'release':'8'},
    {'reference':'gvfs-devel-1.36.2-10.el8', 'cpu':'x86_64', 'release':'8'},
    {'reference':'gvfs-fuse-1.36.2-10.el8', 'cpu':'aarch64', 'release':'8'},
    {'reference':'gvfs-fuse-1.36.2-10.el8', 'cpu':'x86_64', 'release':'8'},
    {'reference':'gvfs-goa-1.36.2-10.el8', 'cpu':'aarch64', 'release':'8'},
    {'reference':'gvfs-goa-1.36.2-10.el8', 'cpu':'x86_64', 'release':'8'},
    {'reference':'gvfs-gphoto2-1.36.2-10.el8', 'cpu':'aarch64', 'release':'8'},
    {'reference':'gvfs-gphoto2-1.36.2-10.el8', 'cpu':'x86_64', 'release':'8'},
    {'reference':'gvfs-mtp-1.36.2-10.el8', 'cpu':'aarch64', 'release':'8'},
    {'reference':'gvfs-mtp-1.36.2-10.el8', 'cpu':'x86_64', 'release':'8'},
    {'reference':'gvfs-smb-1.36.2-10.el8', 'cpu':'aarch64', 'release':'8'},
    {'reference':'gvfs-smb-1.36.2-10.el8', 'cpu':'x86_64', 'release':'8'},
    {'reference':'LibRaw-0.19.5-2.el8', 'cpu':'i686', 'release':'8'},
    {'reference':'LibRaw-0.19.5-2.el8', 'cpu':'x86_64', 'release':'8'},
    {'reference':'LibRaw-devel-0.19.5-2.el8', 'cpu':'i686', 'release':'8'},
    {'reference':'LibRaw-devel-0.19.5-2.el8', 'cpu':'x86_64', 'release':'8'},
    {'reference':'libsoup-2.62.3-2.el8', 'cpu':'aarch64', 'release':'8'},
    {'reference':'libsoup-2.62.3-2.el8', 'cpu':'i686', 'release':'8'},
    {'reference':'libsoup-2.62.3-2.el8', 'cpu':'x86_64', 'release':'8'},
    {'reference':'libsoup-devel-2.62.3-2.el8', 'cpu':'aarch64', 'release':'8'},
    {'reference':'libsoup-devel-2.62.3-2.el8', 'cpu':'i686', 'release':'8'},
    {'reference':'libsoup-devel-2.62.3-2.el8', 'cpu':'x86_64', 'release':'8'},
    {'reference':'mutter-3.32.2-48.el8', 'cpu':'aarch64', 'release':'8'},
    {'reference':'mutter-3.32.2-48.el8', 'cpu':'i686', 'release':'8'},
    {'reference':'mutter-3.32.2-48.el8', 'cpu':'x86_64', 'release':'8'},
    {'reference':'mutter-devel-3.32.2-48.el8', 'cpu':'aarch64', 'release':'8'},
    {'reference':'mutter-devel-3.32.2-48.el8', 'cpu':'i686', 'release':'8'},
    {'reference':'mutter-devel-3.32.2-48.el8', 'cpu':'x86_64', 'release':'8'},
    {'reference':'nautilus-3.28.1-14.el8', 'cpu':'aarch64', 'release':'8'},
    {'reference':'nautilus-3.28.1-14.el8', 'cpu':'i686', 'release':'8'},
    {'reference':'nautilus-3.28.1-14.el8', 'cpu':'x86_64', 'release':'8'},
    {'reference':'nautilus-devel-3.28.1-14.el8', 'cpu':'aarch64', 'release':'8'},
    {'reference':'nautilus-devel-3.28.1-14.el8', 'cpu':'i686', 'release':'8'},
    {'reference':'nautilus-devel-3.28.1-14.el8', 'cpu':'x86_64', 'release':'8'},
    {'reference':'nautilus-extensions-3.28.1-14.el8', 'cpu':'aarch64', 'release':'8'},
    {'reference':'nautilus-extensions-3.28.1-14.el8', 'cpu':'i686', 'release':'8'},
    {'reference':'nautilus-extensions-3.28.1-14.el8', 'cpu':'x86_64', 'release':'8'},
    {'reference':'PackageKit-1.1.12-6.0.1.el8', 'cpu':'aarch64', 'release':'8'},
    {'reference':'PackageKit-1.1.12-6.0.1.el8', 'cpu':'x86_64', 'release':'8'},
    {'reference':'PackageKit-command-not-found-1.1.12-6.0.1.el8', 'cpu':'aarch64', 'release':'8'},
    {'reference':'PackageKit-command-not-found-1.1.12-6.0.1.el8', 'cpu':'x86_64', 'release':'8'},
    {'reference':'PackageKit-cron-1.1.12-6.0.1.el8', 'cpu':'aarch64', 'release':'8'},
    {'reference':'PackageKit-cron-1.1.12-6.0.1.el8', 'cpu':'x86_64', 'release':'8'},
    {'reference':'PackageKit-glib-1.1.12-6.0.1.el8', 'cpu':'aarch64', 'release':'8'},
    {'reference':'PackageKit-glib-1.1.12-6.0.1.el8', 'cpu':'i686', 'release':'8'},
    {'reference':'PackageKit-glib-1.1.12-6.0.1.el8', 'cpu':'x86_64', 'release':'8'},
    {'reference':'PackageKit-glib-devel-1.1.12-6.0.1.el8', 'cpu':'aarch64', 'release':'8'},
    {'reference':'PackageKit-glib-devel-1.1.12-6.0.1.el8', 'cpu':'i686', 'release':'8'},
    {'reference':'PackageKit-glib-devel-1.1.12-6.0.1.el8', 'cpu':'x86_64', 'release':'8'},
    {'reference':'PackageKit-gstreamer-plugin-1.1.12-6.0.1.el8', 'cpu':'aarch64', 'release':'8'},
    {'reference':'PackageKit-gstreamer-plugin-1.1.12-6.0.1.el8', 'cpu':'x86_64', 'release':'8'},
    {'reference':'PackageKit-gtk3-module-1.1.12-6.0.1.el8', 'cpu':'aarch64', 'release':'8'},
    {'reference':'PackageKit-gtk3-module-1.1.12-6.0.1.el8', 'cpu':'i686', 'release':'8'},
    {'reference':'PackageKit-gtk3-module-1.1.12-6.0.1.el8', 'cpu':'x86_64', 'release':'8'},
    {'reference':'pipewire-0.3.6-1.el8', 'cpu':'aarch64', 'release':'8'},
    {'reference':'pipewire-0.3.6-1.el8', 'cpu':'i686', 'release':'8'},
    {'reference':'pipewire-0.3.6-1.el8', 'cpu':'x86_64', 'release':'8'},
    {'reference':'pipewire-devel-0.3.6-1.el8', 'cpu':'aarch64', 'release':'8'},
    {'reference':'pipewire-devel-0.3.6-1.el8', 'cpu':'i686', 'release':'8'},
    {'reference':'pipewire-devel-0.3.6-1.el8', 'cpu':'x86_64', 'release':'8'},
    {'reference':'pipewire-doc-0.3.6-1.el8', 'cpu':'aarch64', 'release':'8'},
    {'reference':'pipewire-doc-0.3.6-1.el8', 'cpu':'x86_64', 'release':'8'},
    {'reference':'pipewire-libs-0.3.6-1.el8', 'cpu':'aarch64', 'release':'8'},
    {'reference':'pipewire-libs-0.3.6-1.el8', 'cpu':'i686', 'release':'8'},
    {'reference':'pipewire-libs-0.3.6-1.el8', 'cpu':'x86_64', 'release':'8'},
    {'reference':'pipewire-utils-0.3.6-1.el8', 'cpu':'aarch64', 'release':'8'},
    {'reference':'pipewire-utils-0.3.6-1.el8', 'cpu':'x86_64', 'release':'8'},
    {'reference':'pipewire0.2-devel-0.2.7-6.el8', 'cpu':'aarch64', 'release':'8'},
    {'reference':'pipewire0.2-devel-0.2.7-6.el8', 'cpu':'i686', 'release':'8'},
    {'reference':'pipewire0.2-devel-0.2.7-6.el8', 'cpu':'x86_64', 'release':'8'},
    {'reference':'pipewire0.2-libs-0.2.7-6.el8', 'cpu':'aarch64', 'release':'8'},
    {'reference':'pipewire0.2-libs-0.2.7-6.el8', 'cpu':'i686', 'release':'8'},
    {'reference':'pipewire0.2-libs-0.2.7-6.el8', 'cpu':'x86_64', 'release':'8'},
    {'reference':'potrace-1.15-3.el8', 'cpu':'aarch64', 'release':'8'},
    {'reference':'potrace-1.15-3.el8', 'cpu':'i686', 'release':'8'},
    {'reference':'potrace-1.15-3.el8', 'cpu':'x86_64', 'release':'8'},
    {'reference':'pygobject3-devel-3.28.3-2.el8', 'cpu':'aarch64', 'release':'8'},
    {'reference':'pygobject3-devel-3.28.3-2.el8', 'cpu':'i686', 'release':'8'},
    {'reference':'pygobject3-devel-3.28.3-2.el8', 'cpu':'x86_64', 'release':'8'},
    {'reference':'python3-gobject-3.28.3-2.el8', 'cpu':'aarch64', 'release':'8'},
    {'reference':'python3-gobject-3.28.3-2.el8', 'cpu':'i686', 'release':'8'},
    {'reference':'python3-gobject-3.28.3-2.el8', 'cpu':'x86_64', 'release':'8'},
    {'reference':'python3-gobject-base-3.28.3-2.el8', 'cpu':'aarch64', 'release':'8'},
    {'reference':'python3-gobject-base-3.28.3-2.el8', 'cpu':'i686', 'release':'8'},
    {'reference':'python3-gobject-base-3.28.3-2.el8', 'cpu':'x86_64', 'release':'8'},
    {'reference':'tracker-2.1.5-2.el8', 'cpu':'aarch64', 'release':'8'},
    {'reference':'tracker-2.1.5-2.el8', 'cpu':'i686', 'release':'8'},
    {'reference':'tracker-2.1.5-2.el8', 'cpu':'x86_64', 'release':'8'},
    {'reference':'tracker-devel-2.1.5-2.el8', 'cpu':'aarch64', 'release':'8'},
    {'reference':'tracker-devel-2.1.5-2.el8', 'cpu':'i686', 'release':'8'},
    {'reference':'tracker-devel-2.1.5-2.el8', 'cpu':'x86_64', 'release':'8'},
    {'reference':'vte-profile-0.52.4-2.el8', 'cpu':'aarch64', 'release':'8'},
    {'reference':'vte-profile-0.52.4-2.el8', 'cpu':'x86_64', 'release':'8'},
    {'reference':'vte291-0.52.4-2.el8', 'cpu':'aarch64', 'release':'8'},
    {'reference':'vte291-0.52.4-2.el8', 'cpu':'i686', 'release':'8'},
    {'reference':'vte291-0.52.4-2.el8', 'cpu':'x86_64', 'release':'8'},
    {'reference':'vte291-devel-0.52.4-2.el8', 'cpu':'aarch64', 'release':'8'},
    {'reference':'vte291-devel-0.52.4-2.el8', 'cpu':'i686', 'release':'8'},
    {'reference':'vte291-devel-0.52.4-2.el8', 'cpu':'x86_64', 'release':'8'},
    {'reference':'webkit2gtk3-2.28.4-1.el8', 'cpu':'aarch64', 'release':'8'},
    {'reference':'webkit2gtk3-2.28.4-1.el8', 'cpu':'i686', 'release':'8'},
    {'reference':'webkit2gtk3-2.28.4-1.el8', 'cpu':'x86_64', 'release':'8'},
    {'reference':'webkit2gtk3-devel-2.28.4-1.el8', 'cpu':'aarch64', 'release':'8'},
    {'reference':'webkit2gtk3-devel-2.28.4-1.el8', 'cpu':'i686', 'release':'8'},
    {'reference':'webkit2gtk3-devel-2.28.4-1.el8', 'cpu':'x86_64', 'release':'8'},
    {'reference':'webkit2gtk3-jsc-2.28.4-1.el8', 'cpu':'aarch64', 'release':'8'},
    {'reference':'webkit2gtk3-jsc-2.28.4-1.el8', 'cpu':'i686', 'release':'8'},
    {'reference':'webkit2gtk3-jsc-2.28.4-1.el8', 'cpu':'x86_64', 'release':'8'},
    {'reference':'webkit2gtk3-jsc-devel-2.28.4-1.el8', 'cpu':'aarch64', 'release':'8'},
    {'reference':'webkit2gtk3-jsc-devel-2.28.4-1.el8', 'cpu':'i686', 'release':'8'},
    {'reference':'webkit2gtk3-jsc-devel-2.28.4-1.el8', 'cpu':'x86_64', 'release':'8'},
    {'reference':'webrtc-audio-processing-0.3-9.el8', 'cpu':'aarch64', 'release':'8'},
    {'reference':'webrtc-audio-processing-0.3-9.el8', 'cpu':'i686', 'release':'8'},
    {'reference':'webrtc-audio-processing-0.3-9.el8', 'cpu':'x86_64', 'release':'8'},
    {'reference':'xdg-desktop-portal-1.6.0-2.el8', 'cpu':'aarch64', 'release':'8'},
    {'reference':'xdg-desktop-portal-1.6.0-2.el8', 'cpu':'x86_64', 'release':'8'},
    {'reference':'xdg-desktop-portal-gtk-1.6.0-1.el8', 'cpu':'aarch64', 'release':'8'},
    {'reference':'xdg-desktop-portal-gtk-1.6.0-1.el8', 'cpu':'x86_64', 'release':'8'}
];

flag = 0;
foreach package_array ( pkgs ) {
  reference = NULL;
  release = NULL;
  sp = NULL;
  cpu = NULL;
  el_string = NULL;
  rpm_spec_vers_cmp = NULL;
  epoch = NULL;
  allowmaj = NULL;
  rpm_prefix = NULL;
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (!empty_or_null(package_array['release'])) release = 'EL' + package_array['release'];
  if (!empty_or_null(package_array['sp'])) sp = package_array['sp'];
  if (!empty_or_null(package_array['cpu'])) cpu = package_array['cpu'];
  if (!empty_or_null(package_array['el_string'])) el_string = package_array['el_string'];
  if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
  if (!empty_or_null(package_array['epoch'])) epoch = package_array['epoch'];
  if (!empty_or_null(package_array['allowmaj'])) allowmaj = package_array['allowmaj'];
  if (!empty_or_null(package_array['rpm_prefix'])) rpm_prefix = package_array['rpm_prefix'];
  if (reference && release) {
    if (rpm_prefix) {
        if (rpm_exists(release:release, rpm:rpm_prefix) && rpm_check(release:release, sp:sp, cpu:cpu, reference:reference, epoch:epoch, el_string:el_string, rpm_spec_vers_cmp:rpm_spec_vers_cmp, allowmaj:allowmaj)) flag++;
    } else {
        if (rpm_check(release:release, sp:sp, cpu:cpu, reference:reference, epoch:epoch, el_string:el_string, rpm_spec_vers_cmp:rpm_spec_vers_cmp, allowmaj:allowmaj)) flag++;
    }
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
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'LibRaw / LibRaw-devel / PackageKit / etc');
}