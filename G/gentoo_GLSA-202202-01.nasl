#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# @NOAGENT@
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 202202-01.
#
# The advisory text is Copyright (C) 2001-2021 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(157266);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/02/03");

  script_cve_id(
    "CVE-2021-1788",
    "CVE-2021-1817",
    "CVE-2021-1820",
    "CVE-2021-1825",
    "CVE-2021-1826",
    "CVE-2021-1844",
    "CVE-2021-1871",
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
    "CVE-2021-30897",
    "CVE-2021-30934",
    "CVE-2021-30936",
    "CVE-2021-30951",
    "CVE-2021-30952",
    "CVE-2021-30953",
    "CVE-2021-30954",
    "CVE-2021-30984",
    "CVE-2021-42762",
    "CVE-2021-45482"
  );
  script_xref(name:"IAVA", value:"2021-A-0126-S");
  script_xref(name:"IAVA", value:"2021-A-0251-S");
  script_xref(name:"IAVA", value:"2021-A-0202-S");
  script_xref(name:"IAVA", value:"2021-A-0212-S");
  script_xref(name:"IAVA", value:"2021-A-0349-S");
  script_xref(name:"IAVA", value:"2021-A-0505-S");
  script_xref(name:"IAVA", value:"2021-A-0414-S");
  script_xref(name:"IAVA", value:"2021-A-0437-S");
  script_xref(name:"IAVA", value:"2021-A-0577-S");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2021/11/17");

  script_name(english:"GLSA-202202-01 : WebkitGTK+: Multiple vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"");
  script_set_attribute(attribute:"description", value:
"The remote host is affected by the vulnerability described in GLSA-202202-01 (WebkitGTK+: Multiple vulnerabilities)

  - A use after free issue was addressed with improved memory management. This issue is fixed in macOS Big Sur
    11.2, Security Update 2021-001 Catalina, Security Update 2021-001 Mojave, tvOS 14.4, watchOS 7.3, iOS 14.4
    and iPadOS 14.4, Safari 14.0.3. Processing maliciously crafted web content may lead to arbitrary code
    execution. (CVE-2021-1788)

  - A memory corruption issue was addressed with improved validation. This issue is fixed in iOS 14.4.1 and
    iPadOS 14.4.1, Safari 14.0.3 (v. 14610.4.3.1.7 and 15610.4.3.1.7), watchOS 7.3.2, macOS Big Sur 11.2.3.
    Processing maliciously crafted web content may lead to arbitrary code execution. (CVE-2021-1844)

  - A logic issue was addressed with improved restrictions. This issue is fixed in macOS Big Sur 11.2,
    Security Update 2021-001 Catalina, Security Update 2021-001 Mojave, iOS 14.4 and iPadOS 14.4. A remote
    attacker may be able to cause arbitrary code execution. Apple is aware of a report that this issue may
    have been actively exploited.. (CVE-2021-1871)

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

  - In WebKitGTK before 2.32.4, there is a use-after-free in WebCore::ContainerNode::firstChild, a different
    vulnerability than CVE-2021-30889. (CVE-2021-45482)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://security.gentoo.org/glsa/202202-01");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=779175");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=801400");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=813489");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=819522");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=820434");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=829723");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=831739");
  script_set_attribute(attribute:"solution", value:
"All WebkitGTK+ users should upgrade to the latest version:

			# emerge --sync
			# emerge --ask --oneshot --verbose >=net-libs/webkit-gtk-2.34.4");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-30954");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/01/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/02/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/02/01");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:webkit-gtk");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Gentoo Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/Gentoo/release", "Host/Gentoo/qpkg-list");

  exit(0);
}
include("qpkg.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/Gentoo/release")) audit(AUDIT_OS_NOT, "Gentoo");
if (!get_kb_item("Host/Gentoo/qpkg-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var flag = 0;

var packages = [
  {
    'name' : "net-libs/webkit-gtk",
    'unaffected' : make_list("ge 2.34.4"),
    'vulnerable' : make_list("lt 2.34.4")
  }
];

foreach package( packages ) {
  if (isnull(package['unaffected'])) package['unaffected'] = make_list();
  if (isnull(package['vulnerable'])) package['vulnerable'] = make_list();
  if (qpkg_check(package: package['name'] , unaffected: package['unaffected'], vulnerable: package['vulnerable'])) flag++;
}


if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_HOLE,
    extra      : qpkg_report_get()
  );
  exit(0);
}
else
{
  var tested = qpkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "WebkitGTK+");
}
