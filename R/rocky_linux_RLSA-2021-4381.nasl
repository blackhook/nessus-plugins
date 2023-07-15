#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
#
# The package checks in this plugin were extracted from
# Rocky Linux Security Advisory RLSA-2021:4381.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(157823);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/25");

  script_cve_id(
    "CVE-2021-21775",
    "CVE-2021-21779",
    "CVE-2021-21806",
    "CVE-2021-30663",
    "CVE-2021-30665",
    "CVE-2021-30682",
    "CVE-2021-30689",
    "CVE-2021-30720",
    "CVE-2021-30734",
    "CVE-2021-30744",
    "CVE-2021-30749",
    "CVE-2021-30758",
    "CVE-2021-30795",
    "CVE-2021-30797",
    "CVE-2021-30799"
  );
  script_xref(name:"RLSA", value:"2021:4381");
  script_xref(name:"IAVA", value:"2021-A-0251-S");
  script_xref(name:"IAVA", value:"2021-A-0212-S");
  script_xref(name:"IAVA", value:"2021-A-0349-S");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2021/11/17");

  script_name(english:"Rocky Linux 8 : GNOME (RLSA-2021:4381)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Rocky Linux host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Rocky Linux 8 host has packages installed that are affected by multiple vulnerabilities as referenced in the
RLSA-2021:4381 advisory.

  - A use-after-free vulnerability exists in the way certain events are processed for ImageLoader objects of
    Webkit WebKitGTK 2.30.4. A specially crafted web page can lead to a potential information leak and further
    memory corruption. In order to trigger the vulnerability, a victim must be tricked into visiting a
    malicious webpage. (CVE-2021-21775)

  - A use-after-free vulnerability exists in the way Webkit's GraphicsContext handles certain events in
    WebKitGTK 2.30.4. A specially crafted web page can lead to a potential information leak and further memory
    corruption. A victim must be tricked into visiting a malicious web page to trigger this vulnerability.
    (CVE-2021-21779)

  - An exploitable use-after-free vulnerability exists in WebKitGTK browser version 2.30.3 x64. A specially
    crafted HTML web page can cause a use-after-free condition, resulting in remote code execution. The victim
    needs to visit a malicious web site to trigger the vulnerability. (CVE-2021-21806)

  - An integer overflow was addressed with improved input validation. This issue is fixed in iOS 14.5.1 and
    iPadOS 14.5.1, tvOS 14.6, iOS 12.5.3, Safari 14.1.1, macOS Big Sur 11.3.1. Processing maliciously crafted
    web content may lead to arbitrary code execution. (CVE-2021-30663)

  - A memory corruption issue was addressed with improved state management. This issue is fixed in watchOS
    7.4.1, iOS 14.5.1 and iPadOS 14.5.1, tvOS 14.6, iOS 12.5.3, macOS Big Sur 11.3.1. Processing maliciously
    crafted web content may lead to arbitrary code execution. Apple is aware of a report that this issue may
    have been actively exploited.. (CVE-2021-30665)

  - A logic issue was addressed with improved restrictions. This issue is fixed in tvOS 14.6, iOS 14.6 and
    iPadOS 14.6, Safari 14.1.1, macOS Big Sur 11.4, watchOS 7.5. A malicious application may be able to leak
    sensitive user information. (CVE-2021-30682)

  - A logic issue was addressed with improved state management. This issue is fixed in tvOS 14.6, iOS 14.6 and
    iPadOS 14.6, Safari 14.1.1, macOS Big Sur 11.4, watchOS 7.5. Processing maliciously crafted web content
    may lead to universal cross site scripting. (CVE-2021-30689)

  - A logic issue was addressed with improved restrictions. This issue is fixed in tvOS 14.6, iOS 14.6 and
    iPadOS 14.6, Safari 14.1.1, macOS Big Sur 11.4, watchOS 7.5. A malicious website may be able to access
    restricted ports on arbitrary servers. (CVE-2021-30720)

  - Multiple memory corruption issues were addressed with improved memory handling. This issue is fixed in
    tvOS 14.6, iOS 14.6 and iPadOS 14.6, Safari 14.1.1, macOS Big Sur 11.4, watchOS 7.5. Processing
    maliciously crafted web content may lead to arbitrary code execution. (CVE-2021-30734, CVE-2021-30749)

  - Description: A cross-origin issue with iframe elements was addressed with improved tracking of security
    origins. This issue is fixed in tvOS 14.6, iOS 14.6 and iPadOS 14.6, Safari 14.1.1, macOS Big Sur 11.4,
    watchOS 7.5. Processing maliciously crafted web content may lead to universal cross site scripting.
    (CVE-2021-30744)

  - A type confusion issue was addressed with improved state handling. This issue is fixed in iOS 14.7, Safari
    14.1.2, macOS Big Sur 11.5, watchOS 7.6, tvOS 14.7. Processing maliciously crafted web content may lead to
    arbitrary code execution. (CVE-2021-30758)

  - A use after free issue was addressed with improved memory management. This issue is fixed in iOS 14.7,
    Safari 14.1.2, macOS Big Sur 11.5, watchOS 7.6, tvOS 14.7. Processing maliciously crafted web content may
    lead to arbitrary code execution. (CVE-2021-30795)

  - This issue was addressed with improved checks. This issue is fixed in iOS 14.7, Safari 14.1.2, macOS Big
    Sur 11.5, watchOS 7.6, tvOS 14.7. Processing maliciously crafted web content may lead to code execution.
    (CVE-2021-30797)

  - Multiple memory corruption issues were addressed with improved memory handling. This issue is fixed in iOS
    14.7, macOS Big Sur 11.5, Security Update 2021-004 Catalina, Security Update 2021-005 Mojave. Processing
    maliciously crafted web content may lead to arbitrary code execution. (CVE-2021-30799)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://errata.rockylinux.org/RLSA-2021:4381");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1651378");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1770302");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1791478");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1813727");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1854679");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1873297");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1873488");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1888404");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1894613");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1897932");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1904139");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1905000");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1909300");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1914925");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1924725");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1925640");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1928794");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1928886");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1935261");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1937416");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1937866");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1938937");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1940026");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1944323");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1944329");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1944333");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1944337");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1944340");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1944343");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1944350");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1944859");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1944862");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1944867");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1949176");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1951086");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1952136");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1955754");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1957705");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1960705");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1962049");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1971507");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1971534");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1972545");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1978287");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1978505");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1978612");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1980441");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1980661");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1981420");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1986863");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1986866");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1986872");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1986874");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1986879");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1986881");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1986883");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1986886");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1986888");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1986890");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1986892");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1986900");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1986902");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1986906");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1987233");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1989035");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1998989");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1999120");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2004170");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-30799");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/04/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/11/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/02/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:LibRaw");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:LibRaw-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:LibRaw-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:LibRaw-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:LibRaw-samples");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:LibRaw-samples-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:LibRaw-static");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:accountsservice");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:accountsservice-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:accountsservice-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:accountsservice-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:accountsservice-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:accountsservice-libs-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:gdm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:gdm-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:gdm-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:gdm-pam-extensions-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:gnome-autoar");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:gnome-autoar-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:gnome-autoar-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:gnome-autoar-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:gnome-calculator");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:gnome-calculator-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:gnome-calculator-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:gnome-classic-session");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:gnome-control-center");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:gnome-control-center-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:gnome-control-center-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:gnome-control-center-filesystem");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:gnome-online-accounts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:gnome-online-accounts-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:gnome-online-accounts-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:gnome-online-accounts-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:gnome-session");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:gnome-session-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:gnome-session-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:gnome-session-kiosk-session");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:gnome-session-wayland-session");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:gnome-session-xsession");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:gnome-settings-daemon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:gnome-settings-daemon-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:gnome-settings-daemon-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:gnome-settings-daemon-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:gnome-shell");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:gnome-shell-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:gnome-shell-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:gnome-shell-extension-apps-menu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:gnome-shell-extension-auto-move-windows");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:gnome-shell-extension-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:gnome-shell-extension-dash-to-dock");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:gnome-shell-extension-desktop-icons");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:gnome-shell-extension-disable-screenshield");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:gnome-shell-extension-drive-menu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:gnome-shell-extension-gesture-inhibitor");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:gnome-shell-extension-heads-up-display");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:gnome-shell-extension-horizontal-workspaces");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:gnome-shell-extension-launch-new-instance");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:gnome-shell-extension-native-window-placement");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:gnome-shell-extension-no-hot-corner");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:gnome-shell-extension-panel-favorites");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:gnome-shell-extension-places-menu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:gnome-shell-extension-screenshot-window-sizer");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:gnome-shell-extension-systemMonitor");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:gnome-shell-extension-top-icons");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:gnome-shell-extension-updates-dialog");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:gnome-shell-extension-user-theme");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:gnome-shell-extension-window-grouper");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:gnome-shell-extension-window-list");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:gnome-shell-extension-windowsNavigator");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:gnome-shell-extension-workspace-indicator");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:gnome-software");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:gnome-software-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:gnome-software-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:gnome-software-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:gsettings-desktop-schemas");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:gsettings-desktop-schemas-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:gtk-update-icon-cache");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:gtk-update-icon-cache-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:gtk3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:gtk3-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:gtk3-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:gtk3-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:gtk3-devel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:gtk3-immodule-xim");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:gtk3-immodule-xim-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:gtk3-immodules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:gtk3-immodules-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:gtk3-tests");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:gtk3-tests-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:mutter");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:mutter-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:mutter-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:mutter-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:vino");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:vino-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:vino-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:webkit2gtk3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:webkit2gtk3-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:webkit2gtk3-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:webkit2gtk3-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:webkit2gtk3-devel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:webkit2gtk3-jsc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:webkit2gtk3-jsc-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:webkit2gtk3-jsc-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:webkit2gtk3-jsc-devel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:rocky:linux:8");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Rocky Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/RockyLinux/release", "Host/RockyLinux/rpm-list", "Host/cpu");

  exit(0);
}


include('audit.inc');
include('global_settings.inc');
include('misc_func.inc');
include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var release = get_kb_item('Host/RockyLinux/release');
if (isnull(release) || 'Rocky Linux' >!< release) audit(AUDIT_OS_NOT, 'Rocky Linux');
var os_ver = pregmatch(pattern: "Rocky(?: Linux)? release ([0-9]+(\.[0-9]+)?)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'Rocky Linux');
var os_ver = os_ver[1];
if (! preg(pattern:"^8([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, 'Rocky Linux 8.x', 'Rocky Linux ' + os_ver);

if (!get_kb_item('Host/RockyLinux/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Rocky Linux', cpu);

var pkgs = [
    {'reference':'accountsservice-0.6.55-2.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'accountsservice-0.6.55-2.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'accountsservice-debuginfo-0.6.55-2.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'accountsservice-debuginfo-0.6.55-2.el8', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'accountsservice-debuginfo-0.6.55-2.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'accountsservice-debugsource-0.6.55-2.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'accountsservice-debugsource-0.6.55-2.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'accountsservice-devel-0.6.55-2.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'accountsservice-devel-0.6.55-2.el8', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'accountsservice-devel-0.6.55-2.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'accountsservice-libs-0.6.55-2.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'accountsservice-libs-0.6.55-2.el8', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'accountsservice-libs-0.6.55-2.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'accountsservice-libs-debuginfo-0.6.55-2.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'accountsservice-libs-debuginfo-0.6.55-2.el8', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'accountsservice-libs-debuginfo-0.6.55-2.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gdm-40.0-15.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gdm-40.0-15.el8', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gdm-40.0-15.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gdm-debuginfo-40.0-15.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gdm-debuginfo-40.0-15.el8', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gdm-debuginfo-40.0-15.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gdm-debugsource-40.0-15.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gdm-debugsource-40.0-15.el8', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gdm-debugsource-40.0-15.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gdm-pam-extensions-devel-40.0-15.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gdm-pam-extensions-devel-40.0-15.el8', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gdm-pam-extensions-devel-40.0-15.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gnome-autoar-0.2.3-2.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gnome-autoar-0.2.3-2.el8', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gnome-autoar-0.2.3-2.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gnome-autoar-debuginfo-0.2.3-2.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gnome-autoar-debuginfo-0.2.3-2.el8', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gnome-autoar-debuginfo-0.2.3-2.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gnome-autoar-debugsource-0.2.3-2.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gnome-autoar-debugsource-0.2.3-2.el8', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gnome-autoar-debugsource-0.2.3-2.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gnome-autoar-devel-0.2.3-2.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gnome-autoar-devel-0.2.3-2.el8', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gnome-autoar-devel-0.2.3-2.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gnome-calculator-3.28.2-2.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gnome-calculator-3.28.2-2.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gnome-calculator-debuginfo-3.28.2-2.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gnome-calculator-debuginfo-3.28.2-2.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gnome-calculator-debugsource-3.28.2-2.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gnome-calculator-debugsource-3.28.2-2.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gnome-classic-session-3.32.1-20.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gnome-classic-session-3.32.1-20.el8_5.1', 'release':'8', 'el_string':'el8_5', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gnome-control-center-3.28.2-28.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gnome-control-center-3.28.2-28.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gnome-control-center-debuginfo-3.28.2-28.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gnome-control-center-debuginfo-3.28.2-28.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gnome-control-center-debugsource-3.28.2-28.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gnome-control-center-debugsource-3.28.2-28.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gnome-control-center-filesystem-3.28.2-28.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gnome-online-accounts-3.28.2-3.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gnome-online-accounts-3.28.2-3.el8', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gnome-online-accounts-3.28.2-3.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gnome-online-accounts-debuginfo-3.28.2-3.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gnome-online-accounts-debuginfo-3.28.2-3.el8', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gnome-online-accounts-debuginfo-3.28.2-3.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gnome-online-accounts-debugsource-3.28.2-3.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gnome-online-accounts-debugsource-3.28.2-3.el8', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gnome-online-accounts-debugsource-3.28.2-3.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gnome-online-accounts-devel-3.28.2-3.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gnome-online-accounts-devel-3.28.2-3.el8', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gnome-online-accounts-devel-3.28.2-3.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gnome-session-3.28.1-13.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gnome-session-3.28.1-13.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gnome-session-debuginfo-3.28.1-13.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gnome-session-debuginfo-3.28.1-13.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gnome-session-debugsource-3.28.1-13.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gnome-session-debugsource-3.28.1-13.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gnome-session-kiosk-session-3.28.1-13.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gnome-session-kiosk-session-3.28.1-13.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gnome-session-wayland-session-3.28.1-13.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gnome-session-wayland-session-3.28.1-13.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gnome-session-xsession-3.28.1-13.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gnome-session-xsession-3.28.1-13.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gnome-settings-daemon-3.32.0-16.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gnome-settings-daemon-3.32.0-16.el8', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gnome-settings-daemon-3.32.0-16.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gnome-settings-daemon-debuginfo-3.32.0-16.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gnome-settings-daemon-debuginfo-3.32.0-16.el8', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gnome-settings-daemon-debuginfo-3.32.0-16.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gnome-settings-daemon-debugsource-3.32.0-16.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gnome-settings-daemon-debugsource-3.32.0-16.el8', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gnome-settings-daemon-debugsource-3.32.0-16.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gnome-settings-daemon-devel-3.32.0-16.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gnome-settings-daemon-devel-3.32.0-16.el8', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gnome-settings-daemon-devel-3.32.0-16.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gnome-shell-3.32.2-40.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gnome-shell-3.32.2-40.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gnome-shell-debuginfo-3.32.2-40.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gnome-shell-debuginfo-3.32.2-40.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gnome-shell-debugsource-3.32.2-40.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gnome-shell-debugsource-3.32.2-40.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gnome-shell-extension-apps-menu-3.32.1-20.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gnome-shell-extension-apps-menu-3.32.1-20.el8_5.1', 'release':'8', 'el_string':'el8_5', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gnome-shell-extension-auto-move-windows-3.32.1-20.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gnome-shell-extension-auto-move-windows-3.32.1-20.el8_5.1', 'release':'8', 'el_string':'el8_5', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gnome-shell-extension-common-3.32.1-20.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gnome-shell-extension-common-3.32.1-20.el8_5.1', 'release':'8', 'el_string':'el8_5', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gnome-shell-extension-dash-to-dock-3.32.1-20.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gnome-shell-extension-dash-to-dock-3.32.1-20.el8_5.1', 'release':'8', 'el_string':'el8_5', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gnome-shell-extension-desktop-icons-3.32.1-20.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gnome-shell-extension-desktop-icons-3.32.1-20.el8_5.1', 'release':'8', 'el_string':'el8_5', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gnome-shell-extension-disable-screenshield-3.32.1-20.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gnome-shell-extension-disable-screenshield-3.32.1-20.el8_5.1', 'release':'8', 'el_string':'el8_5', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gnome-shell-extension-drive-menu-3.32.1-20.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gnome-shell-extension-drive-menu-3.32.1-20.el8_5.1', 'release':'8', 'el_string':'el8_5', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gnome-shell-extension-gesture-inhibitor-3.32.1-20.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gnome-shell-extension-gesture-inhibitor-3.32.1-20.el8_5.1', 'release':'8', 'el_string':'el8_5', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gnome-shell-extension-heads-up-display-3.32.1-20.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gnome-shell-extension-heads-up-display-3.32.1-20.el8_5.1', 'release':'8', 'el_string':'el8_5', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gnome-shell-extension-horizontal-workspaces-3.32.1-20.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gnome-shell-extension-horizontal-workspaces-3.32.1-20.el8_5.1', 'release':'8', 'el_string':'el8_5', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gnome-shell-extension-launch-new-instance-3.32.1-20.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gnome-shell-extension-launch-new-instance-3.32.1-20.el8_5.1', 'release':'8', 'el_string':'el8_5', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gnome-shell-extension-native-window-placement-3.32.1-20.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gnome-shell-extension-native-window-placement-3.32.1-20.el8_5.1', 'release':'8', 'el_string':'el8_5', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gnome-shell-extension-no-hot-corner-3.32.1-20.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gnome-shell-extension-no-hot-corner-3.32.1-20.el8_5.1', 'release':'8', 'el_string':'el8_5', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gnome-shell-extension-panel-favorites-3.32.1-20.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gnome-shell-extension-panel-favorites-3.32.1-20.el8_5.1', 'release':'8', 'el_string':'el8_5', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gnome-shell-extension-places-menu-3.32.1-20.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gnome-shell-extension-places-menu-3.32.1-20.el8_5.1', 'release':'8', 'el_string':'el8_5', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gnome-shell-extension-screenshot-window-sizer-3.32.1-20.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gnome-shell-extension-screenshot-window-sizer-3.32.1-20.el8_5.1', 'release':'8', 'el_string':'el8_5', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gnome-shell-extension-systemMonitor-3.32.1-20.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gnome-shell-extension-systemMonitor-3.32.1-20.el8_5.1', 'release':'8', 'el_string':'el8_5', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gnome-shell-extension-top-icons-3.32.1-20.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gnome-shell-extension-top-icons-3.32.1-20.el8_5.1', 'release':'8', 'el_string':'el8_5', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gnome-shell-extension-updates-dialog-3.32.1-20.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gnome-shell-extension-updates-dialog-3.32.1-20.el8_5.1', 'release':'8', 'el_string':'el8_5', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gnome-shell-extension-user-theme-3.32.1-20.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gnome-shell-extension-user-theme-3.32.1-20.el8_5.1', 'release':'8', 'el_string':'el8_5', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gnome-shell-extension-window-grouper-3.32.1-20.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gnome-shell-extension-window-grouper-3.32.1-20.el8_5.1', 'release':'8', 'el_string':'el8_5', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gnome-shell-extension-window-list-3.32.1-20.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gnome-shell-extension-window-list-3.32.1-20.el8_5.1', 'release':'8', 'el_string':'el8_5', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gnome-shell-extension-windowsNavigator-3.32.1-20.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gnome-shell-extension-windowsNavigator-3.32.1-20.el8_5.1', 'release':'8', 'el_string':'el8_5', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gnome-shell-extension-workspace-indicator-3.32.1-20.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gnome-shell-extension-workspace-indicator-3.32.1-20.el8_5.1', 'release':'8', 'el_string':'el8_5', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gnome-software-3.36.1-10.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gnome-software-3.36.1-10.el8', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gnome-software-3.36.1-10.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gnome-software-debuginfo-3.36.1-10.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gnome-software-debuginfo-3.36.1-10.el8', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gnome-software-debuginfo-3.36.1-10.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gnome-software-debugsource-3.36.1-10.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gnome-software-debugsource-3.36.1-10.el8', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gnome-software-debugsource-3.36.1-10.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gnome-software-devel-3.36.1-10.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gnome-software-devel-3.36.1-10.el8', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gnome-software-devel-3.36.1-10.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gsettings-desktop-schemas-3.32.0-6.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gsettings-desktop-schemas-3.32.0-6.el8', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gsettings-desktop-schemas-3.32.0-6.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gsettings-desktop-schemas-devel-3.32.0-6.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gsettings-desktop-schemas-devel-3.32.0-6.el8', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gsettings-desktop-schemas-devel-3.32.0-6.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gtk-update-icon-cache-3.22.30-8.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gtk-update-icon-cache-3.22.30-8.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gtk-update-icon-cache-debuginfo-3.22.30-8.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gtk-update-icon-cache-debuginfo-3.22.30-8.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gtk3-3.22.30-8.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gtk3-3.22.30-8.el8', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gtk3-3.22.30-8.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gtk3-debuginfo-3.22.30-8.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gtk3-debuginfo-3.22.30-8.el8', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gtk3-debuginfo-3.22.30-8.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gtk3-debugsource-3.22.30-8.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gtk3-debugsource-3.22.30-8.el8', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gtk3-debugsource-3.22.30-8.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gtk3-devel-3.22.30-8.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gtk3-devel-3.22.30-8.el8', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gtk3-devel-3.22.30-8.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gtk3-devel-debuginfo-3.22.30-8.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gtk3-devel-debuginfo-3.22.30-8.el8', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gtk3-devel-debuginfo-3.22.30-8.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gtk3-immodule-xim-3.22.30-8.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gtk3-immodule-xim-3.22.30-8.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gtk3-immodule-xim-debuginfo-3.22.30-8.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gtk3-immodule-xim-debuginfo-3.22.30-8.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gtk3-immodules-3.22.30-8.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gtk3-immodules-3.22.30-8.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gtk3-immodules-debuginfo-3.22.30-8.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gtk3-immodules-debuginfo-3.22.30-8.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gtk3-tests-3.22.30-8.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gtk3-tests-3.22.30-8.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gtk3-tests-debuginfo-3.22.30-8.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gtk3-tests-debuginfo-3.22.30-8.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'LibRaw-0.19.5-3.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'LibRaw-0.19.5-3.el8', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'LibRaw-0.19.5-3.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'LibRaw-debuginfo-0.19.5-3.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'LibRaw-debuginfo-0.19.5-3.el8', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'LibRaw-debuginfo-0.19.5-3.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'LibRaw-debugsource-0.19.5-3.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'LibRaw-debugsource-0.19.5-3.el8', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'LibRaw-debugsource-0.19.5-3.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'LibRaw-devel-0.19.5-3.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'LibRaw-devel-0.19.5-3.el8', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'LibRaw-devel-0.19.5-3.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'LibRaw-samples-0.19.5-3.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'LibRaw-samples-0.19.5-3.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'LibRaw-samples-debuginfo-0.19.5-3.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'LibRaw-samples-debuginfo-0.19.5-3.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'LibRaw-static-0.19.5-3.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'LibRaw-static-0.19.5-3.el8', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'LibRaw-static-0.19.5-3.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'mutter-3.32.2-60.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'mutter-3.32.2-60.el8', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'mutter-3.32.2-60.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'mutter-debuginfo-3.32.2-60.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'mutter-debuginfo-3.32.2-60.el8', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'mutter-debuginfo-3.32.2-60.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'mutter-debugsource-3.32.2-60.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'mutter-debugsource-3.32.2-60.el8', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'mutter-debugsource-3.32.2-60.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'mutter-devel-3.32.2-60.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'mutter-devel-3.32.2-60.el8', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'mutter-devel-3.32.2-60.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'vino-3.22.0-11.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'vino-3.22.0-11.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'vino-debuginfo-3.22.0-11.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'vino-debuginfo-3.22.0-11.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'vino-debugsource-3.22.0-11.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'vino-debugsource-3.22.0-11.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'webkit2gtk3-2.32.3-2.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'webkit2gtk3-2.32.3-2.el8', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'webkit2gtk3-2.32.3-2.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'webkit2gtk3-debuginfo-2.32.3-2.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'webkit2gtk3-debuginfo-2.32.3-2.el8', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'webkit2gtk3-debuginfo-2.32.3-2.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'webkit2gtk3-debugsource-2.32.3-2.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'webkit2gtk3-debugsource-2.32.3-2.el8', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'webkit2gtk3-debugsource-2.32.3-2.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'webkit2gtk3-devel-2.32.3-2.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'webkit2gtk3-devel-2.32.3-2.el8', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'webkit2gtk3-devel-2.32.3-2.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'webkit2gtk3-devel-debuginfo-2.32.3-2.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'webkit2gtk3-devel-debuginfo-2.32.3-2.el8', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'webkit2gtk3-devel-debuginfo-2.32.3-2.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'webkit2gtk3-jsc-2.32.3-2.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'webkit2gtk3-jsc-2.32.3-2.el8', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'webkit2gtk3-jsc-2.32.3-2.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'webkit2gtk3-jsc-debuginfo-2.32.3-2.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'webkit2gtk3-jsc-debuginfo-2.32.3-2.el8', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'webkit2gtk3-jsc-debuginfo-2.32.3-2.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'webkit2gtk3-jsc-devel-2.32.3-2.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'webkit2gtk3-jsc-devel-2.32.3-2.el8', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'webkit2gtk3-jsc-devel-2.32.3-2.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'webkit2gtk3-jsc-devel-debuginfo-2.32.3-2.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'webkit2gtk3-jsc-devel-debuginfo-2.32.3-2.el8', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'webkit2gtk3-jsc-devel-debuginfo-2.32.3-2.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE}
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
  if (!empty_or_null(package_array['release'])) release = 'Rocky-' + package_array['release'];
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'LibRaw / LibRaw-debuginfo / LibRaw-debugsource / LibRaw-devel / etc');
}
