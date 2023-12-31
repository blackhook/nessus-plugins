#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 200403-13.
#
# The advisory text is Copyright (C) 2001-2015 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(14464);
  script_version("1.12");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/06");

  script_cve_id("CVE-2004-0386");
  script_xref(name:"GLSA", value:"200403-13");

  script_name(english:"GLSA-200403-13 : Remote buffer overflow in MPlayer");
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
"The remote host is affected by the vulnerability described in GLSA-200403-13
(Remote buffer overflow in MPlayer)

    A vulnerability exists in the MPlayer HTTP parser which may allow an
    attacker to craft a special HTTP header ('Location:') which will trick
    MPlayer into executing arbitrary code on the user's computer.
  
Impact :

    An attacker without privileges may exploit this vulnerability remotely,
    allowing arbitrary code to be executed in order to gain unauthorized
    access.
  
Workaround :

    A workaround is not currently known for this issue. All users are
    advised to upgrade to the latest version of the affected package."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://mplayerhq.hu"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mplayerhq.hu/homepage/design6/news.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/200403-13"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"MPlayer may be upgraded as follows:
    x86 and SPARC users should:
    # emerge sync
    # emerge -pv '>=media-video/mplayer-0.92-r1'
    # emerge '>=media-video/mplayer-0.92-r1'
    AMD64 users should:
    # emerge sync
    # emerge -pv '>=media-video/mplayer-1.0_pre2-r1'
    # emerge '>=media-video/mplayer-1.0_pre2-r1'
    PPC users should:
    # emerge sync
    # emerge -pv '>=media-video/mplayer-1.0_pre3-r2'
    # emerge '>=media-video/mplayer-1.0_pre3-r2'"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:mplayer");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2004/03/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2004/08/30");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2004-2021 Tenable Network Security, Inc.");
  script_family(english:"Gentoo Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/Gentoo/release", "Host/Gentoo/qpkg-list", "Host/Gentoo/arch");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("qpkg.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/Gentoo/release")) audit(AUDIT_OS_NOT, "Gentoo");
if (!get_kb_item("Host/Gentoo/qpkg-list")) audit(AUDIT_PACKAGE_LIST_MISSING);
ourarch = get_kb_item("Host/Gentoo/arch");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(ppc)$") audit(AUDIT_ARCH_NOT, "ppc", ourarch);

flag = 0;

if (qpkg_check(package:"media-video/mplayer", arch:"ppc", unaffected:make_list("ge 1.0_pre3-r3"), vulnerable:make_list("le 1.0_pre3"))) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "media-video/mplayer");
}
