#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux 2 Security Advisory ALAS-2023-2088.
##

include('compat.inc');

if (description)
{
  script_id(177194);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/06/14");

  script_cve_id(
    "CVE-2020-22592",
    "CVE-2020-27918",
    "CVE-2020-29623",
    "CVE-2021-1765",
    "CVE-2021-1788",
    "CVE-2021-1789",
    "CVE-2021-1799",
    "CVE-2021-1801",
    "CVE-2021-1817",
    "CVE-2021-1820",
    "CVE-2021-1825",
    "CVE-2021-1826",
    "CVE-2021-1844",
    "CVE-2021-1870",
    "CVE-2021-21775",
    "CVE-2021-21779",
    "CVE-2021-21806",
    "CVE-2021-30661",
    "CVE-2021-30663",
    "CVE-2021-30665",
    "CVE-2021-30666",
    "CVE-2021-30682",
    "CVE-2021-30689",
    "CVE-2021-30720",
    "CVE-2021-30734",
    "CVE-2021-30744",
    "CVE-2021-30749",
    "CVE-2021-30758",
    "CVE-2021-30761",
    "CVE-2021-30762",
    "CVE-2021-30795",
    "CVE-2021-30797",
    "CVE-2021-30799",
    "CVE-2021-30809",
    "CVE-2021-30818",
    "CVE-2021-30836",
    "CVE-2021-30846",
    "CVE-2021-30848",
    "CVE-2021-30849",
    "CVE-2021-30851",
    "CVE-2021-30887",
    "CVE-2021-30888",
    "CVE-2021-30889",
    "CVE-2021-30890",
    "CVE-2021-30934",
    "CVE-2021-30936",
    "CVE-2021-30951",
    "CVE-2021-30952",
    "CVE-2021-30953",
    "CVE-2021-30954",
    "CVE-2021-30984",
    "CVE-2021-32912",
    "CVE-2021-42762",
    "CVE-2021-45481",
    "CVE-2021-45482",
    "CVE-2021-45483",
    "CVE-2022-22590",
    "CVE-2022-22592",
    "CVE-2022-22662",
    "CVE-2022-22677",
    "CVE-2022-26700",
    "CVE-2022-26709",
    "CVE-2022-26710",
    "CVE-2022-26716",
    "CVE-2022-26717",
    "CVE-2022-26719",
    "CVE-2022-30293",
    "CVE-2022-32792",
    "CVE-2022-32793",
    "CVE-2022-32816",
    "CVE-2022-32885",
    "CVE-2022-32888",
    "CVE-2022-32923",
    "CVE-2022-42799",
    "CVE-2022-42824",
    "CVE-2022-42826",
    "CVE-2022-42852",
    "CVE-2022-42856",
    "CVE-2022-42863",
    "CVE-2022-42867",
    "CVE-2022-46691",
    "CVE-2022-46692",
    "CVE-2022-46698",
    "CVE-2022-46699",
    "CVE-2022-46700",
    "CVE-2023-2203",
    "CVE-2023-23517",
    "CVE-2023-23518",
    "CVE-2023-23529",
    "CVE-2023-25358",
    "CVE-2023-25360",
    "CVE-2023-25361",
    "CVE-2023-25362",
    "CVE-2023-25363",
    "CVE-2023-27932",
    "CVE-2023-27954",
    "CVE-2023-28204",
    "CVE-2023-28205",
    "CVE-2023-32373",
    "CVE-2023-32409"
  );
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2021/11/17");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/05/25");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2023/01/04");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2023/03/07");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2023/05/01");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2023/06/12");

  script_name(english:"Amazon Linux 2 : webkitgtk4 (ALAS-2023-2088)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Amazon Linux 2 host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The version of webkitgtk4 installed on the remote host is prior to 2.38.5-3. It is, therefore, affected by multiple
vulnerabilities as referenced in the ALAS2-2023-2088 advisory.

  - A use after free issue was addressed with improved memory management. This issue is fixed in macOS Big Sur
    11.0.1, watchOS 7.1, iOS 14.2 and iPadOS 14.2, iCloud for Windows 11.5, Safari 14.0.1, tvOS 14.2, iTunes
    12.11 for Windows. Processing maliciously crafted web content may lead to arbitrary code execution.
    (CVE-2020-27918)

  - Clear History and Website Data did not clear the history. The issue was addressed with improved data
    deletion. This issue is fixed in macOS Big Sur 11.1, Security Update 2020-001 Catalina, Security Update
    2020-007 Mojave, iOS 14.3 and iPadOS 14.3, tvOS 14.3. A user may be unable to fully delete browsing
    history. (CVE-2020-29623)

  - This issue was addressed with improved iframe sandbox enforcement. This issue is fixed in macOS Big Sur
    11.2, Security Update 2021-001 Catalina, Security Update 2021-001 Mojave. Maliciously crafted web content
    may violate iframe sandboxing policy. (CVE-2021-1765)

  - A use after free issue was addressed with improved memory management. This issue is fixed in macOS Big Sur
    11.2, Security Update 2021-001 Catalina, Security Update 2021-001 Mojave, tvOS 14.4, watchOS 7.3, iOS 14.4
    and iPadOS 14.4, Safari 14.0.3. Processing maliciously crafted web content may lead to arbitrary code
    execution. (CVE-2021-1788)

  - A type confusion issue was addressed with improved state handling. This issue is fixed in macOS Big Sur
    11.2, Security Update 2021-001 Catalina, Security Update 2021-001 Mojave, tvOS 14.4, watchOS 7.3, iOS 14.4
    and iPadOS 14.4, Safari 14.0.3. Processing maliciously crafted web content may lead to arbitrary code
    execution. (CVE-2021-1789)

  - A port redirection issue was addressed with additional port validation. This issue is fixed in macOS Big
    Sur 11.2, Security Update 2021-001 Catalina, Security Update 2021-001 Mojave, tvOS 14.4, watchOS 7.3, iOS
    14.4 and iPadOS 14.4, Safari 14.0.3. A malicious website may be able to access restricted ports on
    arbitrary servers. (CVE-2021-1799)

  - This issue was addressed with improved iframe sandbox enforcement. This issue is fixed in macOS Big Sur
    11.2, Security Update 2021-001 Catalina, Security Update 2021-001 Mojave, watchOS 7.3, tvOS 14.4, iOS 14.4
    and iPadOS 14.4. Maliciously crafted web content may violate iframe sandboxing policy. (CVE-2021-1801)

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
    have been actively exploited.. (CVE-2021-1870)

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

  - A use after free issue was addressed with improved memory management. This issue is fixed in Safari 14.1,
    iOS 12.5.3, iOS 14.5 and iPadOS 14.5, watchOS 7.4, tvOS 14.5, macOS Big Sur 11.3. Processing maliciously
    crafted web content may lead to arbitrary code execution. Apple is aware of a report that this issue may
    have been actively exploited.. (CVE-2021-30661)

  - An integer overflow was addressed with improved input validation. This issue is fixed in iOS 14.5.1 and
    iPadOS 14.5.1, tvOS 14.6, iOS 12.5.3, Safari 14.1.1, macOS Big Sur 11.3.1. Processing maliciously crafted
    web content may lead to arbitrary code execution. (CVE-2021-30663)

  - A memory corruption issue was addressed with improved state management. This issue is fixed in watchOS
    7.4.1, iOS 14.5.1 and iPadOS 14.5.1, tvOS 14.6, iOS 12.5.3, macOS Big Sur 11.3.1. Processing maliciously
    crafted web content may lead to arbitrary code execution. Apple is aware of a report that this issue may
    have been actively exploited.. (CVE-2021-30665)

  - A buffer overflow issue was addressed with improved memory handling. This issue is fixed in iOS 12.5.3.
    Processing maliciously crafted web content may lead to arbitrary code execution. Apple is aware of a
    report that this issue may have been actively exploited.. (CVE-2021-30666)

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

  - A memory corruption issue was addressed with improved state management. This issue is fixed in iOS 12.5.4.
    Processing maliciously crafted web content may lead to arbitrary code execution. Apple is aware of a
    report that this issue may have been actively exploited.. (CVE-2021-30761)

  - A use after free issue was addressed with improved memory management. This issue is fixed in iOS 12.5.4.
    Processing maliciously crafted web content may lead to arbitrary code execution. Apple is aware of a
    report that this issue may have been actively exploited.. (CVE-2021-30762)

  - A use after free issue was addressed with improved memory management. This issue is fixed in iOS 14.7,
    Safari 14.1.2, macOS Big Sur 11.5, watchOS 7.6, tvOS 14.7. Processing maliciously crafted web content may
    lead to arbitrary code execution. (CVE-2021-30795)

  - This issue was addressed with improved checks. This issue is fixed in iOS 14.7, Safari 14.1.2, macOS Big
    Sur 11.5, watchOS 7.6, tvOS 14.7. Processing maliciously crafted web content may lead to code execution.
    (CVE-2021-30797)

  - Multiple memory corruption issues were addressed with improved memory handling. This issue is fixed in iOS
    14.7, macOS Big Sur 11.5, Security Update 2021-004 Catalina, Security Update 2021-005 Mojave. Processing
    maliciously crafted web content may lead to arbitrary code execution. (CVE-2021-30799)

  - A use after free issue was addressed with improved memory management. This issue is fixed in Safari 15,
    tvOS 15, watchOS 8, iOS 15 and iPadOS 15. Processing maliciously crafted web content may lead to arbitrary
    code execution. (CVE-2021-30809)

  - A type confusion issue was addressed with improved state handling. This issue is fixed in iOS 14.8 and
    iPadOS 14.8, tvOS 15, iOS 15 and iPadOS 15, Safari 15, watchOS 8. Processing maliciously crafted web
    content may lead to arbitrary code execution. (CVE-2021-30818)

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

  - BubblewrapLauncher.cpp in WebKitGTK and WPE WebKit before 2.34.1 allows a limited sandbox bypass that
    allows a sandboxed process to trick host processes into thinking the sandboxed process is not confined by
    the sandbox, by abusing VFS syscalls that manipulate its filesystem namespace. The impact is limited to
    host services that create UNIX sockets that WebKit mounts inside its sandbox, and the sandboxed process
    remains otherwise confined. NOTE: this is similar to CVE-2021-41133. (CVE-2021-42762)

  - In WebKitGTK before 2.32.4, there is incorrect memory allocation in
    WebCore::ImageBufferCairoImageSurfaceBackend::create, leading to a segmentation violation and application
    crash, a different vulnerability than CVE-2021-30889. (CVE-2021-45481)

  - In WebKitGTK before 2.32.4, there is a use-after-free in WebCore::ContainerNode::firstChild, a different
    vulnerability than CVE-2021-30889. (CVE-2021-45482)

  - In WebKitGTK before 2.32.4, there is a use-after-free in WebCore::Frame::page, a different vulnerability
    than CVE-2021-30889. (CVE-2021-45483)

  - A use after free issue was addressed with improved memory management. This issue is fixed in iOS 15.3 and
    iPadOS 15.3, watchOS 8.4, tvOS 15.3, Safari 15.3, macOS Monterey 12.2. Processing maliciously crafted web
    content may lead to arbitrary code execution. (CVE-2022-22590)

  - A logic issue was addressed with improved state management. This issue is fixed in iOS 15.3 and iPadOS
    15.3, watchOS 8.4, tvOS 15.3, Safari 15.3, macOS Monterey 12.2. Processing maliciously crafted web content
    may prevent Content Security Policy from being enforced. (CVE-2022-22592)

  - A cookie management issue was addressed with improved state management. This issue is fixed in Security
    Update 2022-003 Catalina, macOS Big Sur 11.6.5. Processing maliciously crafted web content may disclose
    sensitive user information. (CVE-2022-22662)

  - A logic issue in the handling of concurrent media was addressed with improved state handling. This issue
    is fixed in macOS Monterey 12.4, iOS 15.5 and iPadOS 15.5. Video self-preview in a webRTC call may be
    interrupted if the user answers a phone call. (CVE-2022-22677)

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

  - An out-of-bounds write issue was addressed with improved input validation. This issue is fixed in iOS 15.6
    and iPadOS 15.6, watchOS 8.7, tvOS 15.6, macOS Monterey 12.5, Safari 15.6. Processing maliciously crafted
    web content may lead to arbitrary code execution. (CVE-2022-32792)

  - Multiple out-of-bounds write issues were addressed with improved bounds checking. This issue is fixed in
    macOS Monterey 12.5, watchOS 8.7, tvOS 15.6, iOS 15.6 and iPadOS 15.6. An app may be able to disclose
    kernel memory. (CVE-2022-32793)

  - The issue was addressed with improved UI handling. This issue is fixed in watchOS 8.7, tvOS 15.6, iOS 15.6
    and iPadOS 15.6, macOS Monterey 12.5. Visiting a website that frames malicious content may lead to UI
    spoofing. (CVE-2022-32816)

  - An out-of-bounds write issue was addressed with improved bounds checking. This issue is fixed in macOS Big
    Sur 11.7, macOS Ventura 13, iOS 16, iOS 15.7 and iPadOS 15.7, watchOS 9, macOS Monterey 12.6, tvOS 16.
    Processing maliciously crafted web content may lead to arbitrary code execution. (CVE-2022-32888)

  - A correctness issue in the JIT was addressed with improved checks. This issue is fixed in tvOS 16.1, iOS
    15.7.1 and iPadOS 15.7.1, macOS Ventura 13, watchOS 9.1, Safari 16.1, iOS 16.1 and iPadOS 16. Processing
    maliciously crafted web content may disclose internal states of the app. (CVE-2022-32923)

  - The issue was addressed with improved UI handling. This issue is fixed in tvOS 16.1, macOS Ventura 13,
    watchOS 9.1, Safari 16.1, iOS 16.1 and iPadOS 16. Visiting a malicious website may lead to user interface
    spoofing. (CVE-2022-42799)

  - A logic issue was addressed with improved state management. This issue is fixed in tvOS 16.1, macOS
    Ventura 13, watchOS 9.1, Safari 16.1, iOS 16.1 and iPadOS 16. Processing maliciously crafted web content
    may disclose sensitive user information. (CVE-2022-42824)

  - A use after free issue was addressed with improved memory management. This issue is fixed in macOS Ventura
    13, iOS 16.1 and iPadOS 16, Safari 16.1. Processing maliciously crafted web content may lead to arbitrary
    code execution. (CVE-2022-42826)

  - The issue was addressed with improved memory handling. This issue is fixed in Safari 16.2, tvOS 16.2,
    macOS Ventura 13.1, iOS 15.7.2 and iPadOS 15.7.2, iOS 16.2 and iPadOS 16.2, watchOS 9.2. Processing
    maliciously crafted web content may result in the disclosure of process memory. (CVE-2022-42852)

  - A type confusion issue was addressed with improved state handling. This issue is fixed in Safari 16.2,
    tvOS 16.2, macOS Ventura 13.1, iOS 15.7.2 and iPadOS 15.7.2, iOS 16.1.2. Processing maliciously crafted
    web content may lead to arbitrary code execution. Apple is aware of a report that this issue may have been
    actively exploited against versions of iOS released before iOS 15.1.. (CVE-2022-42856)

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

  - A flaw was found in the WebKitGTK package. An improper input validation issue may lead to a use-after-free
    vulnerability. This flaw allows attackers with network access to pass specially crafted web content files,
    causing a denial of service or arbitrary code execution. This CVE exists because of a CVE-2023-28205
    security regression for the WebKitGTK package in Red Hat Enterprise Linux 8.8 and Red Hat Enterprise Linux
    9.2. (CVE-2023-2203)

  - The issue was addressed with improved memory handling. This issue is fixed in macOS Ventura 13.2, macOS
    Monterey 12.6.3, tvOS 16.3, Safari 16.3, watchOS 9.3, iOS 16.3 and iPadOS 16.3, macOS Big Sur 11.7.3.
    Processing maliciously crafted web content may lead to arbitrary code execution. (CVE-2023-23517,
    CVE-2023-23518)

  - A type confusion issue was addressed with improved checks. This issue is fixed in macOS Ventura 13.2.1,
    iOS 16.3.1 and iPadOS 16.3.1, Safari 16.3. Processing maliciously crafted web content may lead to
    arbitrary code execution. Apple is aware of a report that this issue may have been actively exploited..
    (CVE-2023-23529)

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

  - This issue was addressed with improved state management. This issue is fixed in macOS Ventura 13.3, tvOS
    16.4, watchOS 9.4, Safari 16.4, iOS 16.4 and iPadOS 16.4. Processing maliciously crafted web content may
    bypass Same Origin Policy (CVE-2023-27932)

  - The issue was addressed by removing origin information. This issue is fixed in macOS Ventura 13.3, iOS
    15.7.4 and iPadOS 15.7.4, tvOS 16.4, watchOS 9.4, Safari 16.4, iOS 16.4 and iPadOS 16.4. A website may be
    able to track sensitive user information (CVE-2023-27954)

  - A use after free issue was addressed with improved memory management. This issue is fixed in macOS Ventura
    13.3.1, iOS 16.4.1 and iPadOS 16.4.1, iOS 15.7.5 and iPadOS 15.7.5, Safari 16.4.1. Processing maliciously
    crafted web content may lead to arbitrary code execution. Apple is aware of a report that this issue may
    have been actively exploited. (CVE-2023-28205)

  - An out-of-bounds read was addressed with improved input validation. (CVE-2023-28204)

  - A use-after-free issue was addressed with improved memory management. (CVE-2023-32373)

  - The issue was addressed with improved bounds checks. (CVE-2023-32409)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/AL2/ALAS-2023-2088.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2020-22592.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2020-27918.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2020-29623.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-1765.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-1788.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-1789.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-1799.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-1801.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-1817.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-1820.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-1825.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-1826.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-1844.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-1870.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-21775.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-21779.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-21806.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-30661.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-30663.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-30665.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-30666.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-30682.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-30689.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-30720.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-30734.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-30744.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-30749.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-30758.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-30761.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-30762.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-30795.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-30797.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-30799.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-30809.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-30818.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-30836.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-30846.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-30848.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-30849.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-30851.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-30887.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-30888.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-30889.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-30890.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-30934.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-30936.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-30951.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-30952.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-30953.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-30954.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-30984.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-32912.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-42762.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-45481.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-45482.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-45483.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-22590.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-22592.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-22662.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-22677.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-26700.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-26709.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-26710.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-26716.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-26717.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-26719.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-30293.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-32792.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-32793.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-32816.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-32885.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-32888.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-32923.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-42799.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-42824.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-42826.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-42852.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-42856.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-42863.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-42867.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-46691.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-46692.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-46698.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-46699.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-46700.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2023-2203.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2023-23517.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2023-23518.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2023-23529.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2023-25358.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2023-25360.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2023-25361.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2023-25362.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2023-25363.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2023-27932.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2023-27954.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2023-28204.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2023-28205.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2023-32373.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2023-32409.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/faqs.html");
  script_set_attribute(attribute:"solution", value:
"Run 'yum update webkitgtk4' to update your system.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-30954");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2021-1870");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/10/31");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/06/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/06/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:webkitgtk4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:webkitgtk4-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:webkitgtk4-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:webkitgtk4-jsc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:webkitgtk4-jsc-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux:2");
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
if (os_ver != "2")
{
  if (os_ver == 'A') os_ver = 'AMI';
  audit(AUDIT_OS_NOT, "Amazon Linux 2", "Amazon Linux " + os_ver);
}

if (!get_kb_item("Host/AmazonLinux/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var pkgs = [
    {'reference':'webkitgtk4-2.38.5-3.amzn2.0.1', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'webkitgtk4-2.38.5-3.amzn2.0.1', 'cpu':'i686', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'webkitgtk4-2.38.5-3.amzn2.0.1', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'webkitgtk4-debuginfo-2.38.5-3.amzn2.0.1', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'webkitgtk4-debuginfo-2.38.5-3.amzn2.0.1', 'cpu':'i686', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'webkitgtk4-debuginfo-2.38.5-3.amzn2.0.1', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'webkitgtk4-devel-2.38.5-3.amzn2.0.1', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'webkitgtk4-devel-2.38.5-3.amzn2.0.1', 'cpu':'i686', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'webkitgtk4-devel-2.38.5-3.amzn2.0.1', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'webkitgtk4-jsc-2.38.5-3.amzn2.0.1', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'webkitgtk4-jsc-2.38.5-3.amzn2.0.1', 'cpu':'i686', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'webkitgtk4-jsc-2.38.5-3.amzn2.0.1', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'webkitgtk4-jsc-devel-2.38.5-3.amzn2.0.1', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'webkitgtk4-jsc-devel-2.38.5-3.amzn2.0.1', 'cpu':'i686', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'webkitgtk4-jsc-devel-2.38.5-3.amzn2.0.1', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "webkitgtk4 / webkitgtk4-debuginfo / webkitgtk4-devel / etc");
}