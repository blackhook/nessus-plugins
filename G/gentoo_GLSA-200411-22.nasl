#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 200411-22.
#
# The advisory text is Copyright (C) 2001-2015 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(15723);
  script_version("1.17");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/06");

  script_cve_id("CVE-2004-0972");
  script_xref(name:"GLSA", value:"200411-22");

  script_name(english:"GLSA-200411-22 : Davfs2, lvm-user: Insecure tempfile handling");
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
"The remote host is affected by the vulnerability described in GLSA-200411-22
(Davfs2, lvm-user: Insecure tempfile handling)

    Florian Schilhabel from the Gentoo Linux Security Audit Team found
    that Davfs2 insecurely created .pid files in /tmp. Furthermore, Trustix
    Secure Linux found that the lvmcreate_initrd script, included in the
    lvm-user Gentoo package, also creates temporary files in
    world-writeable directories with predictable names.
  
Impact :

    A local attacker could create symbolic links in the temporary
    files directory, pointing to a valid file somewhere on the filesystem.
    When Davfs2 or lvmcreate_initrd is called, this would result in the
    file being overwritten with the rights of the user running the
    software, which could be the root user.
  
Workaround :

    There is no known workaround at this time."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/200411-22"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All Davfs2 users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose '>=net-fs/davfs2-0.2.2-r1'
    All lvm-user users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose '>=sys-fs/lvm-user-1.0.7-r2'"
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:N/I:P/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:davfs2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:lvm-user");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2004/11/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2004/11/16");
  script_set_attribute(attribute:"vuln_publication_date", value:"2004/11/12");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2004-2021 Tenable Network Security, Inc.");
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

if (qpkg_check(package:"net-fs/davfs2", unaffected:make_list("ge 0.2.2-r1"), vulnerable:make_list("lt 0.2.2-r1"))) flag++;
if (qpkg_check(package:"sys-fs/lvm-user", unaffected:make_list("ge 1.0.7-r2"), vulnerable:make_list("lt 1.0.7-r2"))) flag++;

if (flag)
{
  if (report_verbosity > 0) security_note(port:0, extra:qpkg_report_get());
  else security_note(0);
  exit(0);
}
else
{
  tested = qpkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "Davfs2 / lvm-user");
}
