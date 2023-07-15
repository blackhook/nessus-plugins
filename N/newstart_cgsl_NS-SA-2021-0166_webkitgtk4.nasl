#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from ZTE advisory NS-SA-2021-0166. The text
# itself is copyright (C) ZTE, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(154614);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/25");

  script_cve_id(
    "CVE-2019-6237",
    "CVE-2019-6251",
    "CVE-2019-7285",
    "CVE-2019-7292",
    "CVE-2019-8503",
    "CVE-2019-8506",
    "CVE-2019-8515",
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
    "CVE-2019-8625",
    "CVE-2019-8644",
    "CVE-2019-8649",
    "CVE-2019-8658",
    "CVE-2019-8666",
    "CVE-2019-8669",
    "CVE-2019-8671",
    "CVE-2019-8672",
    "CVE-2019-8673",
    "CVE-2019-8674",
    "CVE-2019-8676",
    "CVE-2019-8677",
    "CVE-2019-8678",
    "CVE-2019-8679",
    "CVE-2019-8680",
    "CVE-2019-8681",
    "CVE-2019-8683",
    "CVE-2019-8684",
    "CVE-2019-8686",
    "CVE-2019-8687",
    "CVE-2019-8688",
    "CVE-2019-8689",
    "CVE-2019-8690",
    "CVE-2019-8707",
    "CVE-2019-8710",
    "CVE-2019-8719",
    "CVE-2019-8720",
    "CVE-2019-8726",
    "CVE-2019-8733",
    "CVE-2019-8735",
    "CVE-2019-8743",
    "CVE-2019-8763",
    "CVE-2019-8764",
    "CVE-2019-8765",
    "CVE-2019-8766",
    "CVE-2019-8768",
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
    "CVE-2019-8821",
    "CVE-2019-8822",
    "CVE-2019-8823",
    "CVE-2019-8835",
    "CVE-2019-8844",
    "CVE-2019-8846",
    "CVE-2019-11070",
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
    "CVE-2020-10018",
    "CVE-2020-11793",
    "CVE-2021-30666",
    "CVE-2021-30761",
    "CVE-2021-30762"
  );
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2021/11/17");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/05/25");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/06/13");

  script_name(english:"NewStart CGSL CORE 5.05 / MAIN 5.05 : webkitgtk4 Multiple Vulnerabilities (NS-SA-2021-0166)");

  script_set_attribute(attribute:"synopsis", value:
"The remote NewStart CGSL host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote NewStart CGSL host, running version CORE 5.05 / MAIN 5.05, has webkitgtk4 packages installed that are
affected by multiple vulnerabilities:

  - WebKitGTK and WPE WebKit prior to version 2.24.1 failed to properly apply configured HTTP proxy settings
    when downloading livestream video (HLS, DASH, or Smooth Streaming), an error resulting in deanonymization.
    This issue was corrected by changing the way livestreams are downloaded. (CVE-2019-11070)

  - Multiple memory corruption issues were addressed with improved memory handling. This issue is fixed in iOS
    12.3, macOS Mojave 10.14.5, tvOS 12.3, Safari 12.1.1, iTunes for Windows 12.9.5, iCloud for Windows 7.12.
    Processing maliciously crafted web content may lead to arbitrary code execution. (CVE-2019-6237,
    CVE-2019-8571, CVE-2019-8584, CVE-2019-8586, CVE-2019-8587, CVE-2019-8594, CVE-2019-8595, CVE-2019-8596,
    CVE-2019-8597, CVE-2019-8608, CVE-2019-8609, CVE-2019-8610, CVE-2019-8611, CVE-2019-8615, CVE-2019-8619)

  - WebKitGTK and WPE WebKit prior to version 2.24.1 are vulnerable to address bar spoofing upon certain
    JavaScript redirections. An attacker could cause malicious web content to be displayed as if for a trusted
    URI. This is similar to the CVE-2018-8383 issue in Microsoft Edge. (CVE-2019-6251)

  - A use after free issue was addressed with improved memory management. This issue is fixed in iOS 12.2,
    tvOS 12.2, Safari 12.1, iTunes 12.9.4 for Windows, iCloud for Windows 7.11. Processing maliciously crafted
    web content may lead to arbitrary code execution. (CVE-2019-7285)

  - A validation issue was addressed with improved logic. This issue is fixed in iOS 12.2, tvOS 12.2, watchOS
    5.2, Safari 12.1, iTunes 12.9.4 for Windows, iCloud for Windows 7.11. Processing maliciously crafted web
    content may result in the disclosure of process memory. (CVE-2019-7292)

  - A logic issue was addressed with improved validation. This issue is fixed in iOS 12.2, tvOS 12.2, Safari
    12.1, iTunes 12.9.4 for Windows, iCloud for Windows 7.11. A malicious website may be able to execute
    scripts in the context of another website. (CVE-2019-8503)

  - A type confusion issue was addressed with improved memory handling. This issue is fixed in iOS 12.2, tvOS
    12.2, watchOS 5.2, Safari 12.1, iTunes 12.9.4 for Windows, iCloud for Windows 7.11. Processing maliciously
    crafted web content may lead to arbitrary code execution. (CVE-2019-8506)

  - A cross-origin issue existed with the fetch API. This was addressed with improved input validation. This
    issue is fixed in iOS 12.2, tvOS 12.2, Safari 12.1, iTunes 12.9.4 for Windows, iCloud for Windows 7.11.
    Processing maliciously crafted web content may disclose sensitive user information. (CVE-2019-8515)

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

  - A logic issue was addressed with improved state management. This issue is fixed in tvOS 13, iTunes for
    Windows 12.10.1, iCloud for Windows 10.7, iCloud for Windows 7.14. Processing maliciously crafted web
    content may lead to universal cross site scripting. (CVE-2019-8625, CVE-2019-8719)

  - Multiple memory corruption issues were addressed with improved memory handling. This issue is fixed in iOS
    12.4, macOS Mojave 10.14.6, tvOS 12.4, Safari 12.1.2, iTunes for Windows 12.9.6, iCloud for Windows 7.13,
    iCloud for Windows 10.6. Processing maliciously crafted web content may lead to arbitrary code execution.
    (CVE-2019-8644, CVE-2019-8666, CVE-2019-8671, CVE-2019-8673, CVE-2019-8677, CVE-2019-8678, CVE-2019-8679,
    CVE-2019-8680, CVE-2019-8681, CVE-2019-8686, CVE-2019-8687)

  - A logic issue existed in the handling of synchronous page loads. This issue was addressed with improved
    state management. This issue is fixed in iOS 12.4, macOS Mojave 10.14.6, tvOS 12.4, Safari 12.1.2, iTunes
    for Windows 12.9.6, iCloud for Windows 7.13, iCloud for Windows 10.6. Processing maliciously crafted web
    content may lead to universal cross site scripting. (CVE-2019-8649)

  - A logic issue was addressed with improved state management. This issue is fixed in iOS 12.4, macOS Mojave
    10.14.6, tvOS 12.4, watchOS 5.3, Safari 12.1.2, iTunes for Windows 12.9.6, iCloud for Windows 7.13, iCloud
    for Windows 10.6. Processing maliciously crafted web content may lead to universal cross site scripting.
    (CVE-2019-8658)

  - Multiple memory corruption issues were addressed with improved memory handling. This issue is fixed in iOS
    12.4, macOS Mojave 10.14.6, tvOS 12.4, watchOS 5.3, Safari 12.1.2, iTunes for Windows 12.9.6, iCloud for
    Windows 7.13, iCloud for Windows 10.6. Processing maliciously crafted web content may lead to arbitrary
    code execution. (CVE-2019-8669, CVE-2019-8672, CVE-2019-8676, CVE-2019-8683, CVE-2019-8684, CVE-2019-8688,
    CVE-2019-8689)

  - A logic issue was addressed with improved state management. This issue is fixed in iOS 13, Safari 13.
    Processing maliciously crafted web content may lead to universal cross site scripting. (CVE-2019-8674)

  - A logic issue existed in the handling of document loads. This issue was addressed with improved state
    management. This issue is fixed in iOS 12.4, macOS Mojave 10.14.6, tvOS 12.4, Safari 12.1.2, iTunes for
    Windows 12.9.6, iCloud for Windows 7.13, iCloud for Windows 10.6. Processing maliciously crafted web
    content may lead to universal cross site scripting. (CVE-2019-8690)

  - Multiple memory corruption issues were addressed with improved memory handling. This issue is fixed in
    tvOS 13, iTunes for Windows 12.10.1, iCloud for Windows 10.7, iCloud for Windows 7.14. Processing
    maliciously crafted web content may lead to arbitrary code execution. (CVE-2019-8707, CVE-2019-8726,
    CVE-2019-8733, CVE-2019-8735)

  - Multiple memory corruption issues were addressed with improved memory handling. This issue is fixed in
    iCloud for Windows 11.0. Processing maliciously crafted web content may lead to arbitrary code execution.
    (CVE-2019-8710)

  - Multiple memory corruption issues were addressed with improved memory handling. This issue is fixed in
    watchOS 6.1. Processing maliciously crafted web content may lead to arbitrary code execution.
    (CVE-2019-8743, CVE-2019-8765)

  - Multiple memory corruption issues were addressed with improved memory handling. This issue is fixed in iOS
    13.1 and iPadOS 13.1, tvOS 13, Safari 13.0.1, iTunes for Windows 12.10.1, iCloud for Windows 10.7, iCloud
    for Windows 7.14. Processing maliciously crafted web content may lead to arbitrary code execution.
    (CVE-2019-8763)

  - A logic issue was addressed with improved state management. This issue is fixed in watchOS 6.1. Processing
    maliciously crafted web content may lead to universal cross site scripting. (CVE-2019-8764)

  - Multiple memory corruption issues were addressed with improved memory handling. This issue is fixed in
    watchOS 6.1, iCloud for Windows 11.0. Processing maliciously crafted web content may lead to arbitrary
    code execution. (CVE-2019-8766)

  - Clear History and Website Data did not clear the history. The issue was addressed with improved data
    deletion. This issue is fixed in macOS Catalina 10.15. A user may be unable to delete browsing history
    items. (CVE-2019-8768)

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
    (CVE-2019-8783, CVE-2019-8814, CVE-2019-8815, CVE-2019-8819, CVE-2019-8821, CVE-2019-8822, CVE-2019-8823)

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

  - WebKitGTK through 2.26.4 and WPE WebKit through 2.26.4 (which are the versions right before 2.28.0)
    contains a memory corruption issue (use-after-free) that may lead to arbitrary code execution. This issue
    has been fixed in 2.28.0 with improved memory handling. (CVE-2020-10018)

  - A use-after-free issue exists in WebKitGTK before 2.28.1 and WPE WebKit before 2.28.1 via crafted web
    content that allows remote attackers to execute arbitrary code or cause a denial of service (memory
    corruption and application crash). (CVE-2020-11793)

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
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/notice/NS-SA-2021-0166");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2019-11070");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2019-6237");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2019-6251");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2019-7285");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2019-7292");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2019-8503");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2019-8506");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2019-8515");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2019-8518");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2019-8523");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2019-8524");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2019-8535");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2019-8536");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2019-8544");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2019-8551");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2019-8558");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2019-8559");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2019-8563");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2019-8571");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2019-8583");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2019-8584");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2019-8586");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2019-8587");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2019-8594");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2019-8595");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2019-8596");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2019-8597");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2019-8601");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2019-8607");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2019-8608");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2019-8609");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2019-8610");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2019-8611");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2019-8615");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2019-8619");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2019-8622");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2019-8623");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2019-8625");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2019-8644");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2019-8649");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2019-8658");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2019-8666");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2019-8669");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2019-8671");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2019-8672");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2019-8673");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2019-8674");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2019-8676");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2019-8677");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2019-8678");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2019-8679");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2019-8680");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2019-8681");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2019-8683");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2019-8684");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2019-8686");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2019-8687");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2019-8688");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2019-8689");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2019-8690");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2019-8707");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2019-8710");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2019-8719");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2019-8720");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2019-8726");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2019-8733");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2019-8735");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2019-8743");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2019-8763");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2019-8764");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2019-8765");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2019-8766");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2019-8768");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2019-8769");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2019-8771");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2019-8782");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2019-8783");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2019-8808");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2019-8811");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2019-8812");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2019-8813");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2019-8814");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2019-8815");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2019-8816");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2019-8819");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2019-8820");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2019-8821");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2019-8822");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2019-8823");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2019-8835");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2019-8844");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2019-8846");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2020-10018");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2020-11793");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2020-3862");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2020-3864");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2020-3865");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2020-3867");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2020-3868");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2020-3885");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2020-3894");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2020-3895");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2020-3897");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2020-3899");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2020-3900");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2020-3901");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2020-3902");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2021-30666");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2021-30761");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2021-30762");
  script_set_attribute(attribute:"solution", value:
"Upgrade the vulnerable CGSL webkitgtk4 packages. Note that updated packages may not be available yet. Please contact ZTE
for more information.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-3899");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2020-10018");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/01/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/09/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/10/28");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:webkitgtk4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:webkitgtk4-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:webkitgtk4-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:webkitgtk4-jsc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:webkitgtk4-jsc-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:webkitgtk4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:webkitgtk4-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:webkitgtk4-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:webkitgtk4-jsc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:webkitgtk4-jsc-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:zte:cgsl_core:5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:zte:cgsl_main:5");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"NewStart CGSL Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/ZTE-CGSL/release", "Host/ZTE-CGSL/rpm-list", "Host/cpu");

  exit(0);
}

include('audit.inc');
include('global_settings.inc');
include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

var release = get_kb_item('Host/ZTE-CGSL/release');
if (isnull(release) || release !~ "^CGSL (MAIN|CORE)") audit(AUDIT_OS_NOT, 'NewStart Carrier Grade Server Linux');

if (release !~ "CGSL CORE 5.05" &&
    release !~ "CGSL MAIN 5.05")
  audit(AUDIT_OS_NOT, 'NewStart CGSL CORE 5.05 / NewStart CGSL MAIN 5.05');

if (!get_kb_item('Host/ZTE-CGSL/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'NewStart Carrier Grade Server Linux', cpu);

var flag = 0;

var pkgs = {
  'CGSL CORE 5.05': [
    'webkitgtk4-2.28.2-2.el7',
    'webkitgtk4-devel-2.28.2-2.el7',
    'webkitgtk4-doc-2.28.2-2.el7',
    'webkitgtk4-jsc-2.28.2-2.el7',
    'webkitgtk4-jsc-devel-2.28.2-2.el7'
  ],
  'CGSL MAIN 5.05': [
    'webkitgtk4-2.28.2-2.el7',
    'webkitgtk4-devel-2.28.2-2.el7',
    'webkitgtk4-doc-2.28.2-2.el7',
    'webkitgtk4-jsc-2.28.2-2.el7',
    'webkitgtk4-jsc-devel-2.28.2-2.el7'
  ]
};
var pkg_list = pkgs[release];

foreach (pkg in pkg_list)
  if (rpm_check(release:'ZTE ' + release, reference:pkg)) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'webkitgtk4');
}
