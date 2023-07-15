#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 201709-22.
#
# The advisory text is Copyright (C) 2001-2020 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(103450);
  script_version("3.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/11");

  script_cve_id("CVE-2017-10053", "CVE-2017-10067", "CVE-2017-10074", "CVE-2017-10078", "CVE-2017-10081", "CVE-2017-10086", "CVE-2017-10087", "CVE-2017-10089", "CVE-2017-10090", "CVE-2017-10096", "CVE-2017-10101", "CVE-2017-10102", "CVE-2017-10105", "CVE-2017-10107", "CVE-2017-10108", "CVE-2017-10109", "CVE-2017-10110", "CVE-2017-10111", "CVE-2017-10114", "CVE-2017-10115", "CVE-2017-10116", "CVE-2017-10117", "CVE-2017-10118", "CVE-2017-10121", "CVE-2017-10125", "CVE-2017-10135", "CVE-2017-10176", "CVE-2017-10193", "CVE-2017-10198", "CVE-2017-10243");
  script_xref(name:"GLSA", value:"201709-22");

  script_name(english:"GLSA-201709-22 : Oracle JDK/JRE, IcedTea: Multiple vulnerabilities");
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
"The remote host is affected by the vulnerability described in GLSA-201709-22
(Oracle JDK/JRE, IcedTea: Multiple vulnerabilities)

    Multiple vulnerabilities have been discovered in Oracle&rsquo;s JRE, JDK and
      IcedTea. Please review the referenced CVE identifiers for details.
  
Impact :

    A remote attacker could possibly execute arbitrary code with the
      privileges of the process, cause a Denial of Service condition, or gain
      access to information.
  
Workaround :

    There is no known workaround at this time."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/201709-22"
  );
  script_set_attribute(
    attribute:"solution",
    value:
"All Oracle JDK binary users should upgrade to the latest version:
      # emerge --sync
      # emerge --ask --oneshot --verbose
      '>=dev-java/oracle-jdk-bin-1.8.0.141'
    All Oracle JRE binary users should upgrade to the latest version:
      # emerge --sync
      # emerge --ask --oneshot --verbose
      '>=dev-java/oracle-jre-bin-1.8.0.141'
    All IcedTea binary 7.x users should upgrade to the latest version:
      # emerge --sync
      # emerge --ask --oneshot --verbose '>=dev-java/icedtea-bin-7.2.6.11'
    All IcedTea binary 3.x users should upgrade to the latest version:
      # emerge --sync
      # emerge --ask --oneshot --verbose '>=dev-java/icedtea-bin-3.5.0'"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:icedtea-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:oracle-jdk-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:oracle-jre-bin");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/08/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/09/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/09/25");
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

if (qpkg_check(package:"dev-java/icedtea-bin", unaffected:make_list("ge 7.2.6.11", "ge 3.5.0"), vulnerable:make_list("lt 7.2.6.11", "lt 3.5.0"))) flag++;
if (qpkg_check(package:"dev-java/oracle-jdk-bin", unaffected:make_list("ge 1.8.0.141"), vulnerable:make_list("lt 1.8.0.141"))) flag++;
if (qpkg_check(package:"dev-java/oracle-jre-bin", unaffected:make_list("ge 1.8.0.141"), vulnerable:make_list("lt 1.8.0.141"))) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "Oracle JDK/JRE / IcedTea");
}
