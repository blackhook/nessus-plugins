#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 201805-08.
#
# The advisory text is Copyright (C) 2001-2018 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(109975);
  script_version("1.3");
  script_cvs_date("Date: 2018/09/04 13:20:07");

  script_cve_id("CVE-2018-2830", "CVE-2018-2831", "CVE-2018-2835", "CVE-2018-2836", "CVE-2018-2837", "CVE-2018-2842", "CVE-2018-2843", "CVE-2018-2844", "CVE-2018-2845", "CVE-2018-2860");
  script_xref(name:"GLSA", value:"201805-08");

  script_name(english:"GLSA-201805-08 : VirtualBox: Multiple vulnerabilities");
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
"The remote host is affected by the vulnerability described in GLSA-201805-08
(VirtualBox: Multiple vulnerabilities)

    Multiple vulnerabilities have been discovered in VirtualBox. Please
      review the CVE identifiers referenced below for details.
  
Impact :

    An attacker could take control of VirtualBox resulting in the execution
      of arbitrary code with the privileges of the process, a Denial of Service
      condition, or other unspecified impacts.
  
Workaround :

    There is no known workaround at this time."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/201805-08"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All VirtualBox users should upgrade to the latest version:
      # emerge --sync
      # emerge --ask --oneshot --verbose '>=app-emulation/virtualbox-5.1.36'
    All VirtualBox binary users should upgrade to the latest version:
      # emerge --sync
      # emerge --ask --oneshot --verbose
      '>=app-emulation/virtualbox-bin-5.1.36.122089'"
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:virtualbox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:virtualbox-bin");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2018/05/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/05/23");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2018 and is owned by Tenable, Inc. or an Affiliate thereof.");
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

if (qpkg_check(package:"app-emulation/virtualbox", unaffected:make_list("ge 5.1.36"), vulnerable:make_list("lt 5.1.36"))) flag++;
if (qpkg_check(package:"app-emulation/virtualbox-bin", unaffected:make_list("ge 5.1.36.122089"), vulnerable:make_list("lt 5.1.36.122089"))) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "VirtualBox");
}
