#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 200804-11.
#
# The advisory text is Copyright (C) 2001-2015 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(31958);
  script_version("1.16");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/06");

  script_cve_id("CVE-2008-1569");
  script_xref(name:"GLSA", value:"200804-11");

  script_name(english:"GLSA-200804-11 : policyd-weight: Insecure temporary file creation");
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
"The remote host is affected by the vulnerability described in GLSA-200804-11
(policyd-weight: Insecure temporary file creation)

    Chris Howells reported that policyd-weight creates and uses the
    '/tmp/.policyd-weight/' directory in an insecure manner.
  
Impact :

    A local attacker could exploit this vulnerability to delete arbitrary
    files or change the ownership to the 'polw' user via symlink attacks.
  
Workaround :

    Set '$LOCKPATH = '/var/run/policyd-weight/'' manually in
    '/etc/policyd-weight.conf'."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/200804-11"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All policyd-weight users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose '>=mail-filter/policyd-weight-0.1.14.17'
    This version changes the default path for sockets to
    '/var/run/policyd-weight', which is only writable by a privileged user.
    Users need to restart policyd-weight immediately after the upgrade due
    to this change."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:N/I:P/A:P");
  script_cwe_id(59);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:policyd-weight");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/04/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/04/17");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2008-2021 Tenable Network Security, Inc.");
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

if (qpkg_check(package:"mail-filter/policyd-weight", unaffected:make_list("ge 0.1.14.17"), vulnerable:make_list("lt 0.1.14.17"))) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "policyd-weight");
}
