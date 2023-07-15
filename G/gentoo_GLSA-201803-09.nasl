#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 201803-09.
#
# The advisory text is Copyright (C) 2001-2018 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(108435);
  script_version("1.2");
  script_cvs_date("Date: 2018/06/07 13:15:38");

  script_cve_id("CVE-2018-6790", "CVE-2018-6791");
  script_xref(name:"GLSA", value:"201803-09");

  script_name(english:"GLSA-201803-09 : KDE Plasma Workspaces: Multiple vulnerabilities");
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
"The remote host is affected by the vulnerability described in GLSA-201803-09
(KDE Plasma Workspaces: Multiple vulnerabilities)

    Multiple vulnerabilities have been discovered in KDE Plasma Workspaces.
      Please review the referenced CVE identifiers for details.
  
Impact :

    An attacker could execute arbitrary commands via specially crafted thumb
      drive&rsquo;s volume labels or obtain sensitive information via specially
      crafted notifications.
  
Workaround :

    Users should mount removable devices with Dolphin instead of the device
      notifier.
    Users should disable notifications."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/201803-09"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All KDE Plasma Workspace users should upgrade to the latest version:
      # emerge --sync
      # emerge --ask --oneshot --verbose
      '>=kde-plasma/plasma-workspace-5.11.5-r1'"
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:P/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:plasma-workspace");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2018/03/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/03/19");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2018 Tenable Network Security, Inc.");
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

if (qpkg_check(package:"kde-plasma/plasma-workspace", unaffected:make_list("ge 5.11.5-r1"), vulnerable:make_list("lt 5.11.5-r1"))) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "KDE Plasma Workspaces");
}
