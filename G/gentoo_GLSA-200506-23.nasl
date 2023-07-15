#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 200506-23.
#
# The advisory text is Copyright (C) 2001-2018 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(18564);
  script_version("1.16");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/06");

  script_cve_id("CVE-2005-2056");
  script_xref(name:"GLSA", value:"200506-23");

  script_name(english:"GLSA-200506-23 : Clam AntiVirus: Denial of Service vulnerability");
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
"The remote host is affected by the vulnerability described in GLSA-200506-23
(Clam AntiVirus: Denial of Service vulnerability)

    Andrew Toller and Stefan Kanthak discovered that a flaw in libmspack's
    Quantum archive decompressor renders Clam AntiVirus vulnerable to a
    Denial of Service attack.
  
Impact :

    A remote attacker could exploit this vulnerability to cause a Denial of
    Service by sending a specially crafted Quantum archive to the server.
  
Workaround :

    There is no known workaround at this time."
  );
  # http://sourceforge.net/project/shownotes.php?release_id=337279
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?be3d5a07"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/200506-23"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All Clam AntiVirus users should upgrade to the latest available
    version:
    # emerge --sync
    # emerge --ask --oneshot --verbose '>=app-antivirus/clamav-0.86.1'"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:N/I:N/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:clamav");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2005/06/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2005/06/27");
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

if (qpkg_check(package:"app-antivirus/clamav", unaffected:make_list("ge 0.86.1"), vulnerable:make_list("lt 0.86.1"))) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "Clam AntiVirus");
}
