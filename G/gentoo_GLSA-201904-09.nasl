#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 201904-09.
#
# The advisory text is Copyright (C) 2001-2020 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(123696);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/09/28");
  script_xref(name:"GLSA", value:"201904-09");

  script_name(english:"GLSA-201904-09 : Xen: Multiple Vulnerabilities");
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
"The remote host is affected by the vulnerability described in GLSA-201904-09
(Xen: Multiple Vulnerabilities)

    Multiple vulnerabilities have been discovered in Xen. Please review the
      referenced XSA security advisories.
  
Impact :

    Please review the referenced XSA security advisories for details.
  
Workaround :

    There is no known workaround at this time."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://xenbits.xen.org/xsa/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/201904-09"
  );
  script_set_attribute(
    attribute:"solution",
    value:
"All Xen users should upgrade to the latest version:
      # emerge --sync
      # emerge --ask --oneshot --verbose '>=app-emulation/xen-4.10.3-r2'
    All Xen pvgrub users should upgrade to the latest version:
      # emerge --sync
      # emerge --ask --oneshot --verbose
      '>=app-emulation/xen-pvgrub-4.10.3-r2'
    All Xen tools users should upgrade to the latest version:
      # emerge --sync
      # emerge --ask --oneshot --verbose
      '>=app-emulation/xen-tools-4.10.3-r2'"
  );
  script_set_attribute(attribute:"risk_factor", value:"Medium");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:xen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:xen-pvgrub");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:xen-tools");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/04/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/04/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/04/04");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2019-2020 and is owned by Tenable, Inc. or an Affiliate thereof.");
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

if (qpkg_check(package:"app-emulation/xen", unaffected:make_list("ge 4.10.3-r1"), vulnerable:make_list("lt 4.10.3-r1"))) flag++;
if (qpkg_check(package:"app-emulation/xen-pvgrub", unaffected:make_list("ge 4.10.3"), vulnerable:make_list("lt 4.10.3"))) flag++;
if (qpkg_check(package:"app-emulation/xen-tools", unaffected:make_list("ge 4.10.3-r2"), vulnerable:make_list("lt 4.10.3-r2"))) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:qpkg_report_get());
  else security_warning(0);
  exit(0);
}
else
{
  tested = qpkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "Xen");
}
