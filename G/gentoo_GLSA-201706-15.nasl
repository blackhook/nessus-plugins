#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 201706-15.
#
# The advisory text is Copyright (C) 2001-2017 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(100675);
  script_version("3.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/11");

  script_cve_id("CVE-2015-2330", "CVE-2015-7096", "CVE-2015-7098", "CVE-2016-1723", "CVE-2016-1724", "CVE-2016-1725", "CVE-2016-1726", "CVE-2016-1727", "CVE-2016-1728", "CVE-2016-4692", "CVE-2016-4743", "CVE-2016-7586", "CVE-2016-7587", "CVE-2016-7589", "CVE-2016-7592", "CVE-2016-7598", "CVE-2016-7599", "CVE-2016-7610", "CVE-2016-7611", "CVE-2016-7623", "CVE-2016-7632", "CVE-2016-7635", "CVE-2016-7639", "CVE-2016-7640", "CVE-2016-7641", "CVE-2016-7642", "CVE-2016-7645", "CVE-2016-7646", "CVE-2016-7648", "CVE-2016-7649", "CVE-2016-7652", "CVE-2016-7654", "CVE-2016-7656", "CVE-2016-9642", "CVE-2016-9643", "CVE-2017-2350", "CVE-2017-2354", "CVE-2017-2355", "CVE-2017-2356", "CVE-2017-2362", "CVE-2017-2363", "CVE-2017-2364", "CVE-2017-2365", "CVE-2017-2366", "CVE-2017-2367", "CVE-2017-2369", "CVE-2017-2371", "CVE-2017-2373", "CVE-2017-2376", "CVE-2017-2377", "CVE-2017-2386", "CVE-2017-2392", "CVE-2017-2394", "CVE-2017-2395", "CVE-2017-2396", "CVE-2017-2405", "CVE-2017-2415", "CVE-2017-2419", "CVE-2017-2433", "CVE-2017-2442", "CVE-2017-2445", "CVE-2017-2446", "CVE-2017-2447", "CVE-2017-2454", "CVE-2017-2455", "CVE-2017-2457", "CVE-2017-2459", "CVE-2017-2460", "CVE-2017-2464", "CVE-2017-2465", "CVE-2017-2466", "CVE-2017-2468", "CVE-2017-2469", "CVE-2017-2470", "CVE-2017-2471", "CVE-2017-2475", "CVE-2017-2476", "CVE-2017-2481", "CVE-2017-2496", "CVE-2017-2504", "CVE-2017-2505", "CVE-2017-2506", "CVE-2017-2508", "CVE-2017-2510", "CVE-2017-2514", "CVE-2017-2515", "CVE-2017-2521", "CVE-2017-2525", "CVE-2017-2526", "CVE-2017-2528", "CVE-2017-2530", "CVE-2017-2531", "CVE-2017-2536", "CVE-2017-2539", "CVE-2017-2544", "CVE-2017-2547", "CVE-2017-2549", "CVE-2017-6980", "CVE-2017-6984");
  script_xref(name:"GLSA", value:"201706-15");

  script_name(english:"GLSA-201706-15 : WebKitGTK+: Multiple vulnerabilities");
  script_summary(english:"Checks for updated package(s) in /var/db/pkg");

  script_set_attribute(
    attribute:"synopsis", 
    value:
"The remote Gentoo host is missing one or more security-related
patches."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The remote host is affected by the vulnerability described in GLSA-201706-15
(WebKitGTK+: Multiple vulnerabilities)

    Multiple vulnerabilities have been discovered in WebKitGTK+. Please
      review the CVE identifiers referenced below for details.
  
Impact :

    A remote attack can use multiple vectors to execute arbitrary code or
      cause a denial of service condition.
  
Workaround :

    There is no known workaround at this time."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/201706-15"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All WebKitGTK+ users should upgrade to the latest version:
      # emerge --sync
      # emerge --ask --oneshot --verbose '>=net-libs/webkit-gtk-2.16.3:4'"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:webkit-gtk");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/06/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/06/08");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"Gentoo Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/Gentoo/release", "Host/Gentoo/qpkg-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("qpkg.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/Gentoo/release")) audit(AUDIT_OS_NOT, "Gentoo");
if (!get_kb_item("Host/Gentoo/qpkg-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


flag = 0;

if (qpkg_check(package:"net-libs/webkit-gtk", unaffected:make_list("ge 2.16.3"), vulnerable:make_list("lt 2.16.3"))) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:qpkg_report_get());
  else security_hole(0);
  exit(0);
}
else
{
  tested = qpkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "WebKitGTK+");
}
