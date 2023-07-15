#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 201810-06.
#
# The advisory text is Copyright (C) 2001-2022 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(118506);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/07/20");

  script_cve_id("CVE-2017-5715", "CVE-2017-5753", "CVE-2017-5754", "CVE-2018-10471", "CVE-2018-10472", "CVE-2018-10981", "CVE-2018-10982", "CVE-2018-12891", "CVE-2018-12892", "CVE-2018-12893", "CVE-2018-15468", "CVE-2018-15469", "CVE-2018-15470", "CVE-2018-3620", "CVE-2018-3646", "CVE-2018-5244", "CVE-2018-7540", "CVE-2018-7541", "CVE-2018-7542");
  script_xref(name:"GLSA", value:"201810-06");

  script_name(english:"GLSA-201810-06 : Xen: Multiple vulnerabilities (Foreshadow) (Meltdown) (Spectre)");
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
"The remote host is affected by the vulnerability described in GLSA-201810-06
(Xen: Multiple vulnerabilities)

    Multiple vulnerabilities have been discovered in Xen. Please review the
      referenced CVE identifiers for details.
  
Impact :

    A local attacker could cause a Denial of Service condition or disclose
      sensitive information.
  
Workaround :

    There is no known workaround at this time."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/201810-06"
  );
  script_set_attribute(
    attribute:"solution",
    value:
"All Xen users should upgrade to the latest version:
      # emerge --sync
      # emerge --ask --oneshot --verbose '>=app-emulation/xen-4.10.1-r2'
    All Xen tools users should upgrade to the latest version:
      # emerge --sync
      # emerge --ask --oneshot --verbose
      '>=app-emulation/xen-tools-4.10.1-r2'"
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-10982");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:xen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:xen-tools");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/01/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/10/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/10/31");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2018-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");
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

if (qpkg_check(package:"app-emulation/xen", unaffected:make_list("ge 4.10.1-r2"), vulnerable:make_list("lt 4.10.1-r2"))) flag++;
if (qpkg_check(package:"app-emulation/xen-tools", unaffected:make_list("ge 4.10.1-r2"), vulnerable:make_list("lt 4.10.1-r2"))) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "Xen");
}
