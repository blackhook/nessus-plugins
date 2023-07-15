#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 200504-12.
#
# The advisory text is Copyright (C) 2001-2018 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(18045);
  script_version("1.17");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/06");

  script_cve_id("CVE-2005-1064");
  script_xref(name:"GLSA", value:"200504-12");

  script_name(english:"GLSA-200504-12 : rsnapshot: Local privilege escalation");
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
"The remote host is affected by the vulnerability described in GLSA-200504-12
(rsnapshot: Local privilege escalation)

    The copy_symlink() subroutine in rsnapshot follows symlinks when
    changing file ownership, instead of changing the ownership of the
    symlink itself.
  
Impact :

    Under certain circumstances, local attackers can exploit this
    vulnerability to take ownership of arbitrary files, resulting in local
    privilege escalation.
  
Workaround :

    The copy_symlink() subroutine is not called if the cmd_cp parameter has
    been enabled."
  );
  # http://www.rsnapshot.org/security/2005/001.html
  script_set_attribute(
    attribute:"see_also",
    value:"https://rsnapshot.org/security/2005/001.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/200504-12"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All rsnapshot users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose app-backup/rsnapshot"
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:rsnapshot");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2005/04/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2005/04/14");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2005-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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

if (qpkg_check(package:"app-backup/rsnapshot", unaffected:make_list("ge 1.2.1", "rge 1.1.7"), vulnerable:make_list("lt 1.2.1"))) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "rsnapshot");
}