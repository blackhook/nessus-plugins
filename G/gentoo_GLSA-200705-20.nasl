#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 200705-20.
#
# The advisory text is Copyright (C) 2001-2015 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(25341);
  script_version("1.15");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/06");

  script_cve_id("CVE-2006-6731", "CVE-2006-6736", "CVE-2006-6737", "CVE-2006-6745");
  script_xref(name:"GLSA", value:"200705-20");

  script_name(english:"GLSA-200705-20 : Blackdown Java: Applet privilege escalation");
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
"The remote host is affected by the vulnerability described in GLSA-200705-20
(Blackdown Java: Applet privilege escalation)

    Chris Evans has discovered multiple buffer overflows in the Sun JDK and
    the Sun JRE possibly related to various AWT and font layout functions.
    Tom Hawtin has discovered an unspecified vulnerability in the Sun JDK
    and the Sun JRE relating to unintended applet data access. He has also
    discovered multiple other unspecified vulnerabilities in the Sun JDK
    and the Sun JRE allowing unintended Java applet or application resource
    acquisition. Additionally, a memory corruption error has been found in
    the handling of GIF images with zero width field blocks.
  
Impact :

    An attacker could entice a user to run a specially crafted Java applet
    or application that could read, write, or execute local files with the
    privileges of the user running the JVM, access data maintained in other
    Java applets, or escalate the privileges of the currently running Java
    applet or application allowing for unauthorized access to system
    resources.
  
Workaround :

    Disable the 'nsplugin' USE flag in order to prevent web applets from
    being run."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/200705-20"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Since there is no fixed update from Blackdown and since the flaw only
    occurs in the applets, the 'nsplugin' USE flag has been masked in the
    portage tree. Emerge the ebuild again in order to fix the
    vulnerability. Another solution is to switch to another Java
    implementation such as the Sun implementation (dev-java/sun-jdk and
    dev-java/sun-jre-bin).
    # emerge --sync
    # emerge --ask --oneshot --verbose 'dev-java/blackdown-jdk'
    # emerge --ask --oneshot --verbose 'dev-java/blackdown-jre'"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:blackdown-jdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:blackdown-jre");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/05/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/05/29");
  script_set_attribute(attribute:"vuln_publication_date", value:"2006/12/19");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2007-2021 Tenable Network Security, Inc.");
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

if (qpkg_check(package:"dev-java/blackdown-jre", unaffected:make_list("ge 1.4.2.03-r14"), vulnerable:make_list("lt 1.4.2.03-r14"))) flag++;
if (qpkg_check(package:"dev-java/blackdown-jdk", unaffected:make_list("ge 1.4.2.03-r14"), vulnerable:make_list("lt 1.4.2.03-r14"))) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "Blackdown Java");
}
