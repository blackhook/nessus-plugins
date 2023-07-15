#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 202012-02.
#
# The advisory text is Copyright (C) 2001-2020 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(143524);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/12/07");
  script_xref(name:"GLSA", value:"202012-02");

  script_name(english:"GLSA-202012-02 : SeaMonkey: Multiple vulnerabilities");
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
"The remote host is affected by the vulnerability described in GLSA-202012-02
(SeaMonkey: Multiple vulnerabilities)

    Multiple vulnerabilities have been discovered in SeaMonkey. Please
      review referenced release notes for more details.
  
Impact :

    Please review the referenced release notes for details.
  
Workaround :

    There is no known workaround at this time."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.seamonkey-project.org/releases/seamonkey2.53.2/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.seamonkey-project.org/releases/seamonkey2.53.3/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.seamonkey-project.org/releases/seamonkey2.53.4/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.seamonkey-project.org/releases/seamonkey2.53.5/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.seamonkey-project.org/releases/seamonkey2.53.5.1/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/202012-02"
  );
  script_set_attribute(
    attribute:"solution",
    value:
"All SeaMonkey users should upgrade to the latest version:
      # emerge --sync
      # emerge --ask --oneshot --verbose '>=www-client/seamonkey-2.53.5.1'
    Gentoo has discontinued support for the SeaMonkey binary package. We
      recommend that users unmerge the SeaMonkey binary package:
    # emerge --unmerge &ldquo;www-client/seamonkey-bin&rdquo;
    NOTE: The Gentoo developer(s) maintaining the SeaMonkey binary package
      have discontinued support at this time. It may be possible that a new
      Gentoo developer will update it at a later date. The alternative is using
      the standard SeaMonkey package."
  );
  script_set_attribute(attribute:"risk_factor", value:"Medium");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:seamonkey");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:seamonkey-bin");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/12/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/12/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/12/07");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");
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

if (qpkg_check(package:"www-client/seamonkey", unaffected:make_list("ge 2.53.5"), vulnerable:make_list("lt 2.53.5.1"))) flag++;
if (qpkg_check(package:"www-client/seamonkey-bin", unaffected:make_list(), vulnerable:make_list("le 2.49.1_rc2"))) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "SeaMonkey");
}
