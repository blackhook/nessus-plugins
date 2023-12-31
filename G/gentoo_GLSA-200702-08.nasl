#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 200702-08.
#
# The advisory text is Copyright (C) 2001-2018 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(24369);
  script_version("1.22");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/06");

  script_cve_id("CVE-2006-6731", "CVE-2006-6736", "CVE-2006-6737", "CVE-2006-6745", "CVE-2007-0243");
  script_bugtraq_id(21673, 21674, 21675, 22085);
  script_xref(name:"GLSA", value:"200702-08");

  script_name(english:"GLSA-200702-08 : AMD64 x86 emulation Sun's J2SE Development Kit: Multiple vulnerabilities");
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
"The remote host is affected by the vulnerability described in GLSA-200702-08
(AMD64 x86 emulation Sun's J2SE Development Kit: Multiple vulnerabilities)

    Chris Evans has discovered multiple buffer overflows in Sun JDK and Sun
    JRE possibly related to various AWT or font layout functions. Tom
    Hawtin has discovered an unspecified vulnerability in Sun JDK and Sun
    JRE relating to unintended applet data access. He has also discovered
    multiple other unspecified vulnerabilities in Sun JDK and Sun JRE
    allowing unintended Java applet or application resource acquisition.
    Additionally, a memory corruption error has been found in the handling
    of GIF images with zero width field blocks.
  
Impact :

    An attacker could entice a user to run a specially crafted Java applet
    or application that could read, write, or execute local files with the
    privileges of the user running the JVM, access data maintained in other
    Java applets, or escalate the privileges of the currently running Java
    applet or application allowing for unauthorized access to system
    resources.
  
Workaround :

    There is no known workaround at this time."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/200702-08"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All AMD64 x86 emulation Sun's J2SE Development Kit users should upgrade
    to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose '>=app-emulation/emul-linux-x86-java-1.5.0.10'"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_cwe_id(119);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:emul-linux-x86-java");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/02/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/02/18");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2007-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (ourarch !~ "^(amd64)$") audit(AUDIT_ARCH_NOT, "amd64", ourarch);

flag = 0;

if (qpkg_check(package:"app-emulation/emul-linux-x86-java", arch:"amd64", unaffected:make_list("ge 1.5.0.10", "rge 1.4.2.19"), vulnerable:make_list("lt 1.5.0.10"))) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "AMD64 x86 emulation Sun's J2SE Development Kit");
}
