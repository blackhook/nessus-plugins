#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 202011-09.
#
# The advisory text is Copyright (C) 2001-2020 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(142843);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/11/17");

  script_cve_id("CVE-2020-10717", "CVE-2020-10761", "CVE-2020-13253", "CVE-2020-13361", "CVE-2020-13362", "CVE-2020-13659", "CVE-2020-13754", "CVE-2020-13791", "CVE-2020-13800", "CVE-2020-14364");
  script_xref(name:"GLSA", value:"202011-09");

  script_name(english:"GLSA-202011-09 : QEMU: Multiple vulnerabilities");
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
"The remote host is affected by the vulnerability described in GLSA-202011-09
(QEMU: Multiple vulnerabilities)

    Multiple vulnerabilities have been discovered in QEMU. Please review the
      CVE identifiers referenced below for details.
  
Impact :

    Please review the referenced CVE identifiers for details.
  
Workaround :

    There is no known workaround at this time."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/202011-09"
  );
  script_set_attribute(
    attribute:"solution",
    value:
"All QEMU users should upgrade to the latest version:
      # emerge --sync
      # emerge --ask --oneshot --verbose '>=app-emulation/qemu-5.1.0-r1'"
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-13754");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:qemu");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/05/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/11/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/11/12");
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

if (qpkg_check(package:"app-emulation/qemu", unaffected:make_list("ge 5.1.0-r1"), vulnerable:make_list("lt 5.1.0-r1"))) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "QEMU");
}
