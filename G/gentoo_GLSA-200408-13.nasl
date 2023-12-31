#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 200408-13.
#
# The advisory text is Copyright (C) 2001-2018 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(14569);
  script_version("1.17");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/06");

  script_xref(name:"GLSA", value:"200408-13");

  script_name(english:"GLSA-200408-13 : kdebase, kdelibs: Multiple security issues");
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
"The remote host is affected by the vulnerability described in GLSA-200408-13
(kdebase, kdelibs: Multiple security issues)

    KDE contains three security issues:
    Insecure handling of temporary files when running KDE applications
    outside of the KDE environment
    DCOPServer creates temporary files in an insecure manner
    The Konqueror browser allows websites to load webpages into a target
    frame of any other open frame-based webpage
  
Impact :

    An attacker could exploit these vulnerabilities to create or overwrite
    files with the permissions of another user, compromise the account of users
    running a KDE application and insert arbitrary frames into an otherwise
    trusted webpage.
  
Workaround :

    There is no known workaround at this time. All users are encouraged to
    upgrade to the latest available version of kdebase."
  );
  # http://www.kde.org/info/security/advisory-20040811-1.txt
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.kde.org/info/security/advisory-20040811-1.txt"
  );
  # http://www.kde.org/info/security/advisory-20040811-2.txt
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.kde.org/info/security/advisory-20040811-2.txt"
  );
  # http://www.kde.org/info/security/advisory-20040811-3.txt
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.kde.org/info/security/advisory-20040811-3.txt"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/200408-13"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All KDE users should upgrade to the latest versions of kdelibs and kdebase:
    # emerge sync
    # emerge -pv '>=kde-base/kdebase-3.2.3-r1'
    # emerge '>=kde-base/kdebase-3.2.3-r1'
    # emerge -pv '>=kde-base/kdelibs-3.2.3-r1'
    # emerge '>=kde-base/kdelibs-3.2.3-r1'"
  );
  script_set_attribute(attribute:"risk_factor", value:"Medium");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:kdebase");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:kdelibs");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2004/08/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2004/08/30");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2004-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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

if (qpkg_check(package:"kde-base/kdebase", unaffected:make_list("ge 3.2.3-r1"), vulnerable:make_list("lt 3.2.3-r1"))) flag++;
if (qpkg_check(package:"kde-base/kdelibs", unaffected:make_list("ge 3.2.3-r1"), vulnerable:make_list("lt 3.2.3-r1"))) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "kdebase / kdelibs");
}
