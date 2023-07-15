#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 202003-52.
#
# The advisory text is Copyright (C) 2001-2022 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(134927);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/16");

  script_cve_id("CVE-2018-10858", "CVE-2018-10918", "CVE-2018-10919", "CVE-2018-1139", "CVE-2018-1140", "CVE-2018-14629", "CVE-2018-16841", "CVE-2018-16851", "CVE-2018-16852", "CVE-2018-16853", "CVE-2018-16857", "CVE-2018-16860", "CVE-2019-10197", "CVE-2019-14861", "CVE-2019-14870", "CVE-2019-14902", "CVE-2019-14907", "CVE-2019-19344");
  script_xref(name:"GLSA", value:"202003-52");

  script_name(english:"GLSA-202003-52 : Samba: Multiple vulnerabilities");
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
"The remote host is affected by the vulnerability described in GLSA-202003-52
(Samba: Multiple vulnerabilities)

    Multiple vulnerabilities have been discovered in Samba. Please review
      the CVE identifiers referenced below for details.
  
Impact :

    A remote attacker could possibly execute arbitrary code, cause a Denial
      of Service condition, conduct a man-in-the-middle attack, or obtain
      sensitive information.
  
Workaround :

    There is no known workaround at this time."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/202003-52"
  );
  script_set_attribute(
    attribute:"solution",
    value:
"All Samba 4.9.x users should upgrade to the latest version:
      # emerge --sync
      # emerge --ask --oneshot --verbose '>=net-fs/samba-4.9.18'
    All Samba 4.10.x users should upgrade to the latest version:
      # emerge --sync
      # emerge --ask --oneshot --verbose '>=net-fs/samba-4.10.13'
    All Samba 4.11.x users should upgrade to the latest version:
      # emerge --sync
      # emerge --ask --oneshot --verbose '>=net-fs/samba-4.11.6'"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-10858");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:samba");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/08/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/03/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/03/26");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2020-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");
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

if (qpkg_check(package:"net-fs/samba", unaffected:make_list("rge 4.9.18", "rge 4.10.13", "rge 4.11.6"), vulnerable:make_list("lt 4.11.6"))) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "Samba");
}
