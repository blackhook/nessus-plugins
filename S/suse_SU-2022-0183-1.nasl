#%NASL_MIN_LEVEL 70300
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# SUSE update advisory SUSE-SU-2022:0183-1. The text itself
# is copyright (C) SUSE.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(157109);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/25");

  script_cve_id(
    "CVE-2018-8518",
    "CVE-2018-8523",
    "CVE-2019-8766",
    "CVE-2019-8768",
    "CVE-2019-8782",
    "CVE-2019-8808",
    "CVE-2019-8815",
    "CVE-2020-3885",
    "CVE-2020-3894",
    "CVE-2020-3895",
    "CVE-2020-3897",
    "CVE-2020-3900",
    "CVE-2020-3901",
    "CVE-2020-3902",
    "CVE-2020-9802",
    "CVE-2020-9803",
    "CVE-2020-9805",
    "CVE-2020-9947",
    "CVE-2020-9948",
    "CVE-2020-9951",
    "CVE-2020-9952",
    "CVE-2020-10018",
    "CVE-2020-13753",
    "CVE-2020-27918",
    "CVE-2020-29623",
    "CVE-2021-1765",
    "CVE-2021-1788",
    "CVE-2021-1817",
    "CVE-2021-1820",
    "CVE-2021-1825",
    "CVE-2021-1826",
    "CVE-2021-1844",
    "CVE-2021-1871",
    "CVE-2021-30661",
    "CVE-2021-30666",
    "CVE-2021-30682",
    "CVE-2021-30761",
    "CVE-2021-30762",
    "CVE-2021-30809",
    "CVE-2021-30818",
    "CVE-2021-30823",
    "CVE-2021-30836",
    "CVE-2021-30846",
    "CVE-2021-30848",
    "CVE-2021-30849",
    "CVE-2021-30851",
    "CVE-2021-30858",
    "CVE-2021-30884",
    "CVE-2021-30887",
    "CVE-2021-30888",
    "CVE-2021-30889",
    "CVE-2021-30890",
    "CVE-2021-30897"
  );
  script_xref(name:"SuSE", value:"SUSE-SU-2022:0183-1");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2021/11/17");
  script_xref(name:"IAVA", value:"2021-A-0126-S");
  script_xref(name:"IAVA", value:"2021-A-0202-S");
  script_xref(name:"IAVA", value:"2021-A-0251-S");
  script_xref(name:"IAVA", value:"2021-A-0414-S");
  script_xref(name:"IAVA", value:"2021-A-0505-S");
  script_xref(name:"IAVA", value:"2018-A-0329-S");
  script_xref(name:"IAVA", value:"2019-A-0373-S");
  script_xref(name:"IAVA", value:"2021-A-0437-S");

  script_name(english:"SUSE SLES15 Security Update : webkit2gtk3 (SUSE-SU-2022:0183-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote SUSE Linux SLES15 host has packages installed that are affected by multiple vulnerabilities as referenced in
the SUSE-SU-2022:0183-1 advisory.

  - An elevation of privilege vulnerability exists when Microsoft SharePoint Server does not properly sanitize
    a specially crafted web request to an affected SharePoint server, aka Microsoft SharePoint Elevation of
    Privilege Vulnerability. This affects Microsoft SharePoint. This CVE ID is unique from CVE-2018-8480,
    CVE-2018-8488, CVE-2018-8498. (CVE-2018-8518)

  - Multiple memory corruption issues were addressed with improved memory handling. This issue is fixed in
    watchOS 6.1, iCloud for Windows 11.0. Processing maliciously crafted web content may lead to arbitrary
    code execution. (CVE-2019-8766)

  - Clear History and Website Data did not clear the history. The issue was addressed with improved data
    deletion. This issue is fixed in macOS Catalina 10.15. A user may be unable to delete browsing history
    items. (CVE-2019-8768)

  - Multiple memory corruption issues were addressed with improved memory handling. This issue is fixed in iOS
    13.2 and iPadOS 13.2, tvOS 13.2, Safari 13.0.3, iTunes for Windows 12.10.2, iCloud for Windows 11.0.
    Processing maliciously crafted web content may lead to arbitrary code execution. (CVE-2019-8782)

  - Multiple memory corruption issues were addressed with improved memory handling. This issue is fixed in iOS
    13.2 and iPadOS 13.2, tvOS 13.2, watchOS 6.1, Safari 13.0.3, iTunes for Windows 12.10.2. Processing
    maliciously crafted web content may lead to arbitrary code execution. (CVE-2019-8808)

  - Multiple memory corruption issues were addressed with improved memory handling. This issue is fixed in iOS
    13.2 and iPadOS 13.2, tvOS 13.2, Safari 13.0.3, iTunes for Windows 12.10.2, iCloud for Windows 11.0,
    iCloud for Windows 7.15. Processing maliciously crafted web content may lead to arbitrary code execution.
    (CVE-2019-8815)

  - WebKitGTK through 2.26.4 and WPE WebKit through 2.26.4 (which are the versions right before 2.28.0)
    contains a memory corruption issue (use-after-free) that may lead to arbitrary code execution. This issue
    has been fixed in 2.28.0 with improved memory handling. (CVE-2020-10018)

  - The bubblewrap sandbox of WebKitGTK and WPE WebKit, prior to 2.28.3, failed to properly block access to
    CLONE_NEWUSER and the TIOCSTI ioctl. CLONE_NEWUSER could potentially be used to confuse xdg-desktop-
    portal, which allows access outside the sandbox. TIOCSTI can be used to directly execute commands outside
    the sandbox by writing to the controlling terminal's input buffer, similar to CVE-2017-5226.
    (CVE-2020-13753)

  - A use after free issue was addressed with improved memory management. This issue is fixed in macOS Big Sur
    11.0.1, watchOS 7.1, iOS 14.2 and iPadOS 14.2, iCloud for Windows 11.5, Safari 14.0.1, tvOS 14.2, iTunes
    12.11 for Windows. Processing maliciously crafted web content may lead to arbitrary code execution.
    (CVE-2020-27918)

  - Clear History and Website Data did not clear the history. The issue was addressed with improved data
    deletion. This issue is fixed in macOS Big Sur 11.1, Security Update 2020-001 Catalina, Security Update
    2020-007 Mojave, iOS 14.3 and iPadOS 14.3, tvOS 14.3. A user may be unable to fully delete browsing
    history. (CVE-2020-29623)

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

  - A use after free issue was addressed with improved memory management. This issue is fixed in watchOS 7.0,
    iOS 14.0 and iPadOS 14.0, iTunes for Windows 12.10.9, iCloud for Windows 11.5, tvOS 14.0, Safari 14.0.
    Processing maliciously crafted web content may lead to arbitrary code execution. (CVE-2020-9947)

  - A type confusion issue was addressed with improved memory handling. This issue is fixed in Safari 14.0.
    Processing maliciously crafted web content may lead to arbitrary code execution. (CVE-2020-9948)

  - A use after free issue was addressed with improved memory management. This issue is fixed in Safari 14.0.
    Processing maliciously crafted web content may lead to arbitrary code execution. (CVE-2020-9951)

  - An input validation issue was addressed with improved input validation. This issue is fixed in iOS 14.0
    and iPadOS 14.0, tvOS 14.0, watchOS 7.0, Safari 14.0, iCloud for Windows 11.4, iCloud for Windows 7.21.
    Processing maliciously crafted web content may lead to a cross site scripting attack. (CVE-2020-9952)

  - This issue was addressed with improved iframe sandbox enforcement. This issue is fixed in macOS Big Sur
    11.2, Security Update 2021-001 Catalina, Security Update 2021-001 Mojave. Maliciously crafted web content
    may violate iframe sandboxing policy. (CVE-2021-1765)

  - A use after free issue was addressed with improved memory management. This issue is fixed in macOS Big Sur
    11.2, Security Update 2021-001 Catalina, Security Update 2021-001 Mojave, tvOS 14.4, watchOS 7.3, iOS 14.4
    and iPadOS 14.4, Safari 14.0.3. Processing maliciously crafted web content may lead to arbitrary code
    execution. (CVE-2021-1788)

  - A memory corruption issue was addressed with improved state management. This issue is fixed in macOS Big
    Sur 11.3, iOS 14.5 and iPadOS 14.5, watchOS 7.4, tvOS 14.5. Processing maliciously crafted web content may
    lead to arbitrary code execution. (CVE-2021-1817)

  - A memory initialization issue was addressed with improved memory handling. This issue is fixed in macOS
    Big Sur 11.3, iOS 14.5 and iPadOS 14.5, watchOS 7.4, tvOS 14.5. Processing maliciously crafted web content
    may result in the disclosure of process memory. (CVE-2021-1820)

  - An input validation issue was addressed with improved input validation. This issue is fixed in iTunes
    12.11.3 for Windows, iCloud for Windows 12.3, macOS Big Sur 11.3, Safari 14.1, watchOS 7.4, tvOS 14.5, iOS
    14.5 and iPadOS 14.5. Processing maliciously crafted web content may lead to a cross site scripting
    attack. (CVE-2021-1825)

  - A logic issue was addressed with improved restrictions. This issue is fixed in macOS Big Sur 11.3, iOS
    14.5 and iPadOS 14.5, watchOS 7.4, tvOS 14.5. Processing maliciously crafted web content may lead to
    universal cross site scripting. (CVE-2021-1826)

  - A memory corruption issue was addressed with improved validation. This issue is fixed in iOS 14.4.1 and
    iPadOS 14.4.1, Safari 14.0.3 (v. 14610.4.3.1.7 and 15610.4.3.1.7), watchOS 7.3.2, macOS Big Sur 11.2.3.
    Processing maliciously crafted web content may lead to arbitrary code execution. (CVE-2021-1844)

  - A logic issue was addressed with improved restrictions. This issue is fixed in macOS Big Sur 11.2,
    Security Update 2021-001 Catalina, Security Update 2021-001 Mojave, iOS 14.4 and iPadOS 14.4. A remote
    attacker may be able to cause arbitrary code execution. Apple is aware of a report that this issue may
    have been actively exploited.. (CVE-2021-1871)

  - A use after free issue was addressed with improved memory management. This issue is fixed in Safari 14.1,
    iOS 12.5.3, iOS 14.5 and iPadOS 14.5, watchOS 7.4, tvOS 14.5, macOS Big Sur 11.3. Processing maliciously
    crafted web content may lead to arbitrary code execution. Apple is aware of a report that this issue may
    have been actively exploited.. (CVE-2021-30661)

  - A buffer overflow issue was addressed with improved memory handling. This issue is fixed in iOS 12.5.3.
    Processing maliciously crafted web content may lead to arbitrary code execution. Apple is aware of a
    report that this issue may have been actively exploited.. (CVE-2021-30666)

  - A logic issue was addressed with improved restrictions. This issue is fixed in tvOS 14.6, iOS 14.6 and
    iPadOS 14.6, Safari 14.1.1, macOS Big Sur 11.4, watchOS 7.5. A malicious application may be able to leak
    sensitive user information. (CVE-2021-30682)

  - A memory corruption issue was addressed with improved state management. This issue is fixed in iOS 12.5.4.
    Processing maliciously crafted web content may lead to arbitrary code execution. Apple is aware of a
    report that this issue may have been actively exploited.. (CVE-2021-30761)

  - A use after free issue was addressed with improved memory management. This issue is fixed in iOS 12.5.4.
    Processing maliciously crafted web content may lead to arbitrary code execution. Apple is aware of a
    report that this issue may have been actively exploited.. (CVE-2021-30762)

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

  - A use after free issue was addressed with improved memory management. This issue is fixed in iOS 14.8 and
    iPadOS 14.8, macOS Big Sur 11.6. Processing maliciously crafted web content may lead to arbitrary code
    execution. Apple is aware of a report that this issue may have been actively exploited. (CVE-2021-30858)

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

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1194019");
  # https://lists.suse.com/pipermail/sle-security-updates/2022-January/010071.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?505f53d0");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2018-8518");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2018-8523");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-8766");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-8768");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-8782");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-8808");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-8815");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-10018");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-13753");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-27918");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-29623");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-3885");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-3894");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-3895");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-3897");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-3900");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-3901");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-3902");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-9802");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-9803");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-9805");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-9947");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-9948");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-9951");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-9952");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-1765");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-1788");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-1817");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-1820");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-1825");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-1826");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-1844");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-1871");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-30661");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-30666");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-30682");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-30761");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-30762");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-30809");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-30818");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-30823");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-30836");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-30846");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-30848");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-30849");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-30851");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-30858");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-30884");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-30887");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-30888");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-30889");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-30890");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-30897");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-3897");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2020-13753");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/10/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/01/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/01/26");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libjavascriptcoregtk-4_0-18");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libwebkit2gtk-4_0-37");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libwebkit2gtk3-lang");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:typelib-1_0-JavaScriptCore-4_0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:typelib-1_0-WebKit2-4_0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:typelib-1_0-WebKit2WebExtension-4_0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:webkit2gtk-4_0-injected-bundles");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:webkit2gtk3-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:15");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"SuSE Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/SuSE/release", "Host/SuSE/rpm-list");

  exit(0);
}


include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item("Host/SuSE/release");
if (isnull(os_release) || os_release !~ "^(SLED|SLES)") audit(AUDIT_OS_NOT, "SUSE");
var os_ver = pregmatch(pattern: "^(SLE(S|D)\d+)", string:os_release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'SUSE');
os_ver = os_ver[1];
if (! preg(pattern:"^(SLES15)$", string:os_ver)) audit(AUDIT_OS_NOT, 'SUSE SLES15', 'SUSE (' + os_ver + ')');

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'SUSE (' + os_ver + ')', cpu);

var service_pack = get_kb_item("Host/SuSE/patchlevel");
if (isnull(service_pack)) service_pack = "0";
if (os_ver == "SLES15" && (! preg(pattern:"^(0|1)$", string:service_pack))) audit(AUDIT_OS_NOT, "SLES15 SP0/1", os_ver + " SP" + service_pack);

var pkgs = [
    {'reference':'libjavascriptcoregtk-4_0-18-2.34.3-3.92.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_BCL-release-15.1', 'SLES_SAP-release-15.1', 'SLE_HPC-ESPOS-release-1']},
    {'reference':'libwebkit2gtk-4_0-37-2.34.3-3.92.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_BCL-release-15.1', 'SLES_SAP-release-15.1', 'SLE_HPC-ESPOS-release-1']},
    {'reference':'libwebkit2gtk3-lang-2.34.3-3.92.1', 'sp':'1', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_BCL-release-15.1', 'SLES_SAP-release-15.1', 'SLE_HPC-ESPOS-release-1']},
    {'reference':'typelib-1_0-JavaScriptCore-4_0-2.34.3-3.92.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_BCL-release-15.1', 'SLES_SAP-release-15.1', 'SLE_HPC-ESPOS-release-1']},
    {'reference':'typelib-1_0-WebKit2-4_0-2.34.3-3.92.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_BCL-release-15.1', 'SLES_SAP-release-15.1', 'SLE_HPC-ESPOS-release-1']},
    {'reference':'typelib-1_0-WebKit2WebExtension-4_0-2.34.3-3.92.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_BCL-release-15.1', 'SLES_SAP-release-15.1', 'SLE_HPC-ESPOS-release-1']},
    {'reference':'webkit2gtk-4_0-injected-bundles-2.34.3-3.92.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_BCL-release-15.1', 'SLES_SAP-release-15.1', 'SLE_HPC-ESPOS-release-1']},
    {'reference':'webkit2gtk3-devel-2.34.3-3.92.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_BCL-release-15.1', 'SLES_SAP-release-15.1', 'SLE_HPC-ESPOS-release-1']},
    {'reference':'libjavascriptcoregtk-4_0-18-2.34.3-3.92.1', 'sp':'0', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15', 'SLE_HPC-ESPOS-release-15', 'SLE_HPC-LTSS-release-15']},
    {'reference':'libwebkit2gtk-4_0-37-2.34.3-3.92.1', 'sp':'0', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15', 'SLE_HPC-ESPOS-release-15', 'SLE_HPC-LTSS-release-15']},
    {'reference':'libwebkit2gtk3-lang-2.34.3-3.92.1', 'sp':'0', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15', 'SLE_HPC-ESPOS-release-15', 'SLE_HPC-LTSS-release-15']},
    {'reference':'typelib-1_0-JavaScriptCore-4_0-2.34.3-3.92.1', 'sp':'0', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15', 'SLE_HPC-ESPOS-release-15', 'SLE_HPC-LTSS-release-15']},
    {'reference':'typelib-1_0-WebKit2-4_0-2.34.3-3.92.1', 'sp':'0', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15', 'SLE_HPC-ESPOS-release-15', 'SLE_HPC-LTSS-release-15']},
    {'reference':'typelib-1_0-WebKit2WebExtension-4_0-2.34.3-3.92.1', 'sp':'0', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15', 'SLE_HPC-ESPOS-release-15', 'SLE_HPC-LTSS-release-15']},
    {'reference':'webkit2gtk-4_0-injected-bundles-2.34.3-3.92.1', 'sp':'0', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15', 'SLE_HPC-ESPOS-release-15', 'SLE_HPC-LTSS-release-15']},
    {'reference':'webkit2gtk3-devel-2.34.3-3.92.1', 'sp':'0', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15', 'SLE_HPC-ESPOS-release-15', 'SLE_HPC-LTSS-release-15']},
    {'reference':'libjavascriptcoregtk-4_0-18-2.34.3-3.92.1', 'sp':'1', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-1']},
    {'reference':'libwebkit2gtk-4_0-37-2.34.3-3.92.1', 'sp':'1', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-1']},
    {'reference':'typelib-1_0-JavaScriptCore-4_0-2.34.3-3.92.1', 'sp':'1', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-1']},
    {'reference':'typelib-1_0-WebKit2-4_0-2.34.3-3.92.1', 'sp':'1', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-1']},
    {'reference':'typelib-1_0-WebKit2WebExtension-4_0-2.34.3-3.92.1', 'sp':'1', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-1']},
    {'reference':'webkit2gtk-4_0-injected-bundles-2.34.3-3.92.1', 'sp':'1', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-1']},
    {'reference':'webkit2gtk3-devel-2.34.3-3.92.1', 'sp':'1', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-1']},
    {'reference':'libjavascriptcoregtk-4_0-18-2.34.3-3.92.1', 'sp':'0', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-15', 'SLE_HPC-LTSS-release-15']},
    {'reference':'libjavascriptcoregtk-4_0-18-2.34.3-3.92.1', 'sp':'0', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-15', 'SLE_HPC-LTSS-release-15']},
    {'reference':'libjavascriptcoregtk-4_0-18-2.34.3-3.92.1', 'sp':'0', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-15', 'SLE_HPC-LTSS-release-15']},
    {'reference':'libwebkit2gtk-4_0-37-2.34.3-3.92.1', 'sp':'0', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-15', 'SLE_HPC-LTSS-release-15']},
    {'reference':'libwebkit2gtk-4_0-37-2.34.3-3.92.1', 'sp':'0', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-15', 'SLE_HPC-LTSS-release-15']},
    {'reference':'libwebkit2gtk-4_0-37-2.34.3-3.92.1', 'sp':'0', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-15', 'SLE_HPC-LTSS-release-15']},
    {'reference':'libwebkit2gtk3-lang-2.34.3-3.92.1', 'sp':'0', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-15', 'SLE_HPC-LTSS-release-15', 'sles-ltss-release-15']},
    {'reference':'typelib-1_0-JavaScriptCore-4_0-2.34.3-3.92.1', 'sp':'0', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-15', 'SLE_HPC-LTSS-release-15']},
    {'reference':'typelib-1_0-JavaScriptCore-4_0-2.34.3-3.92.1', 'sp':'0', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-15', 'SLE_HPC-LTSS-release-15']},
    {'reference':'typelib-1_0-JavaScriptCore-4_0-2.34.3-3.92.1', 'sp':'0', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-15', 'SLE_HPC-LTSS-release-15']},
    {'reference':'typelib-1_0-WebKit2-4_0-2.34.3-3.92.1', 'sp':'0', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-15', 'SLE_HPC-LTSS-release-15']},
    {'reference':'typelib-1_0-WebKit2-4_0-2.34.3-3.92.1', 'sp':'0', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-15', 'SLE_HPC-LTSS-release-15']},
    {'reference':'typelib-1_0-WebKit2-4_0-2.34.3-3.92.1', 'sp':'0', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-15', 'SLE_HPC-LTSS-release-15']},
    {'reference':'typelib-1_0-WebKit2WebExtension-4_0-2.34.3-3.92.1', 'sp':'0', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-15', 'SLE_HPC-LTSS-release-15']},
    {'reference':'typelib-1_0-WebKit2WebExtension-4_0-2.34.3-3.92.1', 'sp':'0', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-15', 'SLE_HPC-LTSS-release-15']},
    {'reference':'typelib-1_0-WebKit2WebExtension-4_0-2.34.3-3.92.1', 'sp':'0', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-15', 'SLE_HPC-LTSS-release-15']},
    {'reference':'webkit2gtk-4_0-injected-bundles-2.34.3-3.92.1', 'sp':'0', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-15', 'SLE_HPC-LTSS-release-15']},
    {'reference':'webkit2gtk-4_0-injected-bundles-2.34.3-3.92.1', 'sp':'0', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-15', 'SLE_HPC-LTSS-release-15']},
    {'reference':'webkit2gtk-4_0-injected-bundles-2.34.3-3.92.1', 'sp':'0', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-15', 'SLE_HPC-LTSS-release-15']},
    {'reference':'webkit2gtk3-devel-2.34.3-3.92.1', 'sp':'0', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-15', 'SLE_HPC-LTSS-release-15']},
    {'reference':'webkit2gtk3-devel-2.34.3-3.92.1', 'sp':'0', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-15', 'SLE_HPC-LTSS-release-15']},
    {'reference':'webkit2gtk3-devel-2.34.3-3.92.1', 'sp':'0', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-15', 'SLE_HPC-LTSS-release-15']},
    {'reference':'libjavascriptcoregtk-4_0-18-2.34.3-3.92.1', 'sp':'1', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'libjavascriptcoregtk-4_0-18-2.34.3-3.92.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'libwebkit2gtk-4_0-37-2.34.3-3.92.1', 'sp':'1', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'libwebkit2gtk-4_0-37-2.34.3-3.92.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'libwebkit2gtk3-lang-2.34.3-3.92.1', 'sp':'1', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1', 'sles-ltss-release-15.1']},
    {'reference':'typelib-1_0-JavaScriptCore-4_0-2.34.3-3.92.1', 'sp':'1', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'typelib-1_0-JavaScriptCore-4_0-2.34.3-3.92.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'typelib-1_0-WebKit2-4_0-2.34.3-3.92.1', 'sp':'1', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'typelib-1_0-WebKit2-4_0-2.34.3-3.92.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'typelib-1_0-WebKit2WebExtension-4_0-2.34.3-3.92.1', 'sp':'1', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'typelib-1_0-WebKit2WebExtension-4_0-2.34.3-3.92.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'webkit2gtk-4_0-injected-bundles-2.34.3-3.92.1', 'sp':'1', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'webkit2gtk-4_0-injected-bundles-2.34.3-3.92.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'webkit2gtk3-devel-2.34.3-3.92.1', 'sp':'1', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'webkit2gtk3-devel-2.34.3-3.92.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'libjavascriptcoregtk-4_0-18-2.34.3-3.92.1', 'sp':'0', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15']},
    {'reference':'libwebkit2gtk-4_0-37-2.34.3-3.92.1', 'sp':'0', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15']},
    {'reference':'typelib-1_0-JavaScriptCore-4_0-2.34.3-3.92.1', 'sp':'0', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15']},
    {'reference':'typelib-1_0-WebKit2-4_0-2.34.3-3.92.1', 'sp':'0', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15']},
    {'reference':'typelib-1_0-WebKit2WebExtension-4_0-2.34.3-3.92.1', 'sp':'0', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15']},
    {'reference':'webkit2gtk-4_0-injected-bundles-2.34.3-3.92.1', 'sp':'0', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15']},
    {'reference':'webkit2gtk3-devel-2.34.3-3.92.1', 'sp':'0', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15']},
    {'reference':'libjavascriptcoregtk-4_0-18-2.34.3-3.92.1', 'sp':'1', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.1']},
    {'reference':'libwebkit2gtk-4_0-37-2.34.3-3.92.1', 'sp':'1', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.1']},
    {'reference':'typelib-1_0-JavaScriptCore-4_0-2.34.3-3.92.1', 'sp':'1', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.1']},
    {'reference':'typelib-1_0-WebKit2-4_0-2.34.3-3.92.1', 'sp':'1', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.1']},
    {'reference':'typelib-1_0-WebKit2WebExtension-4_0-2.34.3-3.92.1', 'sp':'1', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.1']},
    {'reference':'webkit2gtk-4_0-injected-bundles-2.34.3-3.92.1', 'sp':'1', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.1']},
    {'reference':'webkit2gtk3-devel-2.34.3-3.92.1', 'sp':'1', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.1']}
];

var ltss_caveat_required = FALSE;
var flag = 0;
foreach var package_array ( pkgs ) {
  var reference = NULL;
  var _release = NULL;
  var sp = NULL;
  var _cpu = NULL;
  var exists_check = NULL;
  var rpm_spec_vers_cmp = NULL;
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (!empty_or_null(package_array['release'])) _release = package_array['release'];
  if (!empty_or_null(package_array['sp'])) sp = package_array['sp'];
  if (!empty_or_null(package_array['cpu'])) _cpu = package_array['cpu'];
  if (!empty_or_null(package_array['exists_check'])) exists_check = package_array['exists_check'];
  if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
  if (reference && _release) {
    if (exists_check) {
      var check_flag = 0;
      foreach var check (exists_check) {
        if (!rpm_exists(release:_release, rpm:check)) continue;
        if ('ltss' >< tolower(check)) ltss_caveat_required = TRUE;
        check_flag++;
      }
      if (!check_flag) continue;
    }
    if (rpm_check(release:_release, sp:sp, cpu:_cpu, reference:reference, rpm_spec_vers_cmp:rpm_spec_vers_cmp)) flag++;
  }
}

if (flag)
{
  var ltss_plugin_caveat = NULL;
  if(ltss_caveat_required) ltss_plugin_caveat = '\n' +
    'NOTE: This vulnerability check contains fixes that apply to\n' +
    'packages only available in SUSE Enterprise Linux Server LTSS\n' +
    'repositories. Access to these package security updates require\n' +
    'a paid SUSE LTSS subscription.\n';
  security_report_v4(
      port       : 0,
      severity   : SECURITY_HOLE,
      extra      : rpm_report_get() + ltss_plugin_caveat
  );
  exit(0);
}
else
{
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'libjavascriptcoregtk-4_0-18 / libwebkit2gtk-4_0-37 / etc');
}
