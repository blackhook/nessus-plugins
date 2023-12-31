#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 200606-23.
#
# The advisory text is Copyright (C) 2001-2018 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(21743);
  script_version("1.16");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/06");

  script_cve_id("CVE-2006-2449");
  script_xref(name:"GLSA", value:"200606-23");

  script_name(english:"GLSA-200606-23 : KDM: Symlink vulnerability");
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
"The remote host is affected by the vulnerability described in GLSA-200606-23
(KDM: Symlink vulnerability)

    Ludwig Nussel discovered that KDM could be tricked into allowing users
    to read files that would otherwise not be readable.
  
Impact :

    A local attacker could exploit this issue to obtain potentially
    sensitive information that is usually not accessable to the local user
    such as shadow files or other user's files. The default Gentoo user
    running KDM is root and, as a result, the local attacker can read any
    file.
  
Workaround :

    There is no known workaround at this time."
  );
  # http://www.kde.org/info/security/advisory-20060614-1.txt
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.kde.org/info/security/advisory-20060614-1.txt"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/200606-23"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All kdebase users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose kde-base/kdebase
    All KDE split ebuild users should upgrade to the latest KDM version:
    # emerge --sync
    # emerge --ask --oneshot --verbose kde-base/kdm"
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:H/Au:N/C:C/I:N/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:kdebase");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:kdm");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2006/06/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/06/23");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2006-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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

if (qpkg_check(package:"kde-base/kdebase", unaffected:make_list("ge 3.5.2-r2", "rge 3.4.3-r2"), vulnerable:make_list("lt 3.5.2-r2"))) flag++;
if (qpkg_check(package:"kde-base/kdm", unaffected:make_list("ge 3.5.2-r1", "rge 3.4.3-r2"), vulnerable:make_list("lt 3.5.2-r1"))) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "KDM");
}
