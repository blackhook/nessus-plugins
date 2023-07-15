#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 201709-12.
#
# The advisory text is Copyright (C) 2001-2020 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(103280);
  script_version("3.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/11");

  script_cve_id("CVE-2017-6512");
  script_xref(name:"GLSA", value:"201709-12");

  script_name(english:"GLSA-201709-12 : Perl: Race condition vulnerability");
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
"The remote host is affected by the vulnerability described in GLSA-201709-12
(Perl: Race condition vulnerability)

    A race condition occurs within concurrent environments. This condition
      was discovered by The cPanel Security Team in the rmtree and remove_tree
      functions in the File-Path module before 2.13 for Perl. This is due to
      the  time-of-check-to-time-of-use (TOCTOU) race condition between the
      stat() that decides the inode is a directory and the chmod() that tries
      to make it user-rwx.
  
Impact :

    A local attacker could exploit this condition to set arbitrary mode
      values on arbitrary files and hence bypass security restrictions.
  
Workaround :

    There is no known workaround at this time."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/201709-12"
  );
  script_set_attribute(
    attribute:"solution",
    value:
"All Perl users should upgrade to the latest version:
      # emerge --sync
      # emerge --ask --oneshot --verbose '>=dev-lang/perl-5.24.1-r2'
    All File-Path users should upgrade to the latest version:
      # emerge --sync
      # emerge --ask --oneshot --verbose '>=perl-core/File-Path-2.130.0'
    All Perl-File-Path users should upgrade to the latest version:
      # emerge --sync
      # emerge --ask --oneshot --verbose '>=virtual/perl-File-Path-2.130.0'"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:H/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:File-Path");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:perl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:perl-File-Path");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/06/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/09/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/09/18");
  script_set_attribute(attribute:"generated_plugin", value:"current");
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

if (qpkg_check(package:"dev-lang/perl", unaffected:make_list("ge 5.24.1-r2"), vulnerable:make_list("lt 5.24.1-r2"))) flag++;
if (qpkg_check(package:"perl-core/File-Path", unaffected:make_list("ge 2.130.0"), vulnerable:make_list("lt 2.130.0"))) flag++;
if (qpkg_check(package:"virtual/perl-File-Path", unaffected:make_list("ge 2.130.0"), vulnerable:make_list("lt 2.130.0"))) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "Perl");
}
