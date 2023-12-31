#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 201309-09.
#
# The advisory text is Copyright (C) 2001-2019 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(69900);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/06");

  script_cve_id("CVE-2013-1438", "CVE-2013-1439", "CVE-2013-2126", "CVE-2013-2127");
  script_bugtraq_id(60174, 60321, 62057, 62060);
  script_xref(name:"GLSA", value:"201309-09");

  script_name(english:"GLSA-201309-09 : LibRaw, libkdcraw: Multiple vulnerabilities");
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
"The remote host is affected by the vulnerability described in GLSA-201309-09
(LibRaw, libkdcraw: Multiple vulnerabilities)

    Multiple vulnerabilities have been discovered in LibRaw and libkdcraw.
      Please review the CVE identifiers referenced below for details.
  
Impact :

    A remote attacker could entice a user to open a specially crafted file,
      possibly resulting in arbitrary code execution or Denial of Service.
  
Workaround :

    There is no known workaround at this time."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/201309-09"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All LibRaw users should upgrade to the latest version:
      # emerge --sync
      # emerge --ask --oneshot --verbose '>=media-libs/libraw-0.15.4'
    All libkdcraw users should upgrade to the latest version:
      # emerge --sync
      # emerge --ask --oneshot --verbose '>=kde-base/libkdcraw-4.10.5-r1'"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:libkdcraw");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:libraw");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/08/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/09/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/09/15");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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

if (qpkg_check(package:"media-libs/libraw", unaffected:make_list("ge 0.15.4"), vulnerable:make_list("lt 0.15.4"))) flag++;
if (qpkg_check(package:"kde-base/libkdcraw", unaffected:make_list("ge 4.10.5-r1"), vulnerable:make_list("lt 4.10.5-r1"))) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "LibRaw / libkdcraw");
}
