#%NASL_MIN_LEVEL 80900
#
# (C) Tenable, Inc.
#
# @NOAGENT@
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 202208-39.
#
# The advisory text is Copyright (C) 2001-2021 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include('compat.inc');

if (description)
{
  script_id(164535);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/08/31");

  script_cve_id(
    "CVE-2022-2294",
    "CVE-2022-22589",
    "CVE-2022-22590",
    "CVE-2022-22592",
    "CVE-2022-22620",
    "CVE-2022-22624",
    "CVE-2022-22628",
    "CVE-2022-22629",
    "CVE-2022-22662",
    "CVE-2022-22677",
    "CVE-2022-26700",
    "CVE-2022-26709",
    "CVE-2022-26710",
    "CVE-2022-26716",
    "CVE-2022-26717",
    "CVE-2022-26719",
    "CVE-2022-30293",
    "CVE-2022-30294",
    "CVE-2022-32784",
    "CVE-2022-32792",
    "CVE-2022-32893"
  );
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/09/08");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/09/15");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/02/25");

  script_name(english:"GLSA-202208-39 : WebKitGTK+: Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"");
  script_set_attribute(attribute:"description", value:
"The remote host is affected by the vulnerability described in GLSA-202208-39 (WebKitGTK+: Multiple Vulnerabilities)

  - A validation issue was addressed with improved input sanitization. This issue is fixed in iOS 15.3 and
    iPadOS 15.3, watchOS 8.4, tvOS 15.3, Safari 15.3, macOS Monterey 12.2. Processing a maliciously crafted
    mail message may lead to running arbitrary javascript. (CVE-2022-22589)

  - A use after free issue was addressed with improved memory management. This issue is fixed in iOS 15.3 and
    iPadOS 15.3, watchOS 8.4, tvOS 15.3, Safari 15.3, macOS Monterey 12.2. Processing maliciously crafted web
    content may lead to arbitrary code execution. (CVE-2022-22590)

  - A logic issue was addressed with improved state management. This issue is fixed in iOS 15.3 and iPadOS
    15.3, watchOS 8.4, tvOS 15.3, Safari 15.3, macOS Monterey 12.2. Processing maliciously crafted web content
    may prevent Content Security Policy from being enforced. (CVE-2022-22592)

  - A use after free issue was addressed with improved memory management. This issue is fixed in macOS
    Monterey 12.2.1, iOS 15.3.1 and iPadOS 15.3.1, Safari 15.3 (v. 16612.4.9.1.8 and 15612.4.9.1.8).
    Processing maliciously crafted web content may lead to arbitrary code execution. Apple is aware of a
    report that this issue may have been actively exploited.. (CVE-2022-22620)

  - A cookie management issue was addressed with improved state management. This issue is fixed in Security
    Update 2022-003 Catalina, macOS Big Sur 11.6.5. Processing maliciously crafted web content may disclose
    sensitive user information. (CVE-2022-22662)

  - Heap buffer overflow in WebRTC in Google Chrome prior to 103.0.5060.114 allowed a remote attacker to
    potentially exploit heap corruption via a crafted HTML page. (CVE-2022-2294)

  - In WebKitGTK through 2.36.0 (and WPE WebKit), there is a heap-based buffer overflow in
    WebCore::TextureMapperLayer::setContentsLayer in WebCore/platform/graphics/texmap/TextureMapperLayer.cpp.
    (CVE-2022-30293)

  - ** REJECT ** DO NOT USE THIS CANDIDATE NUMBER. ConsultIDs: CVE-2022-30293. Reason: This candidate is a
    duplicate of CVE-2022-30293. Notes: All CVE users should reference CVE-2022-30293 instead of this
    candidate. All references and descriptions in this candidate have been removed to prevent accidental
    usage. (CVE-2022-30294)

  - An out-of-bounds write issue was addressed with improved bounds checking. This issue is fixed in iOS
    15.6.1 and iPadOS 15.6.1, macOS Monterey 12.5.1, Safari 15.6.1. Processing maliciously crafted web content
    may lead to arbitrary code execution. Apple is aware of a report that this issue may have been actively
    exploited. (CVE-2022-32893)

  - A use after free issue was addressed with improved memory management. (CVE-2022-22624, CVE-2022-22628,
    CVE-2022-26709, CVE-2022-26710, CVE-2022-26717)

  - A buffer overflow issue was addressed with improved memory handling. (CVE-2022-22629)

  - A logic issue in the handling of concurrent media was addressed with improved state handling.
    (CVE-2022-22677)

  - A memory corruption issue was addressed with improved state management. (CVE-2022-26700, CVE-2022-26716,
    CVE-2022-26719)

  - The issue was addressed with improved UI handling. (CVE-2022-32784)

  - An out-of-bounds write issue was addressed with improved input validation. (CVE-2022-32792)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://security.gentoo.org/glsa/202208-39");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=832990");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=833568");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=837305");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=839984");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=845252");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=856445");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=861740");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=864427");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=866494");
  script_set_attribute(attribute:"solution", value:
"All WebKitGTK+ users should upgrade to the latest version:

          # emerge --sync
          # emerge --ask --oneshot --verbose >=net-libs/webkit-gtk-2.36.7");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-30294");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/01/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/08/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/08/31");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:webkit-gtk");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");
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
    'unaffected' : make_list("ge 2.36.7", "lt 2.0.0"),
    'vulnerable' : make_list("lt 2.36.7")
  }
];

foreach package( packages ) {
  if (isnull(package['unaffected'])) package['unaffected'] = make_list();
  if (isnull(package['vulnerable'])) package['vulnerable'] = make_list();
  if (qpkg_check(package: package['name'] , unaffected: package['unaffected'], vulnerable: package['vulnerable'])) flag++;
}

# This plugin has a different number of unaffected and vulnerable versions for
# one or more packages. To ensure proper detection, a separate line should be 
# used for each fixed/vulnerable version pair.

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
  qpkg_tests = list_uniq(qpkg_tests);
  var tested = qpkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "WebKitGTK+");
}
