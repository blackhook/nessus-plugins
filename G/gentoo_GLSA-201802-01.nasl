#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 201802-01.
#
# The advisory text is Copyright (C) 2001-2020 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(106739);
  script_version("3.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/09/28");

  script_cve_id("CVE-2018-2676", "CVE-2018-2685", "CVE-2018-2686", "CVE-2018-2687", "CVE-2018-2688", "CVE-2018-2689", "CVE-2018-2690", "CVE-2018-2693", "CVE-2018-2694", "CVE-2018-2698");
  script_xref(name:"GLSA", value:"201802-01");

  script_name(english:"GLSA-201802-01 : VirtualBox: Multiple vulnerabilities");
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
"The remote host is affected by the vulnerability described in GLSA-201802-01
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
    value:"https://security.gentoo.org/glsa/201802-01"
  );
  script_set_attribute(
    attribute:"solution",
    value:
"All VirtualBox users should upgrade to the latest version:
      # emerge --sync
      # emerge --ask --oneshot --verbose '>=app-emulation/virtualbox-5.1.32'
    All VirtualBox Binary users should upgrade to the latest version:
      # emerge --sync
      # emerge --ask --oneshot --verbose
      '>=app-emulation/virtualbox-bin-5.1.32.120294'
    All VirtualBox Guest Additions users should upgrade to the latest
      version:
      # emerge --sync
      # emerge --ask --oneshot --verbose
      '>=app-emulation/virtualbox-guest-additions-5.1.32'"
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:virtualbox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:virtualbox-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:virtualbox-guest-additions");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/01/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/02/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/02/12");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2018-2020 and is owned by Tenable, Inc. or an Affiliate thereof.");
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

if (qpkg_check(package:"app-emulation/virtualbox", unaffected:make_list("ge 5.1.32"), vulnerable:make_list("lt 5.1.32"))) flag++;
if (qpkg_check(package:"app-emulation/virtualbox-bin", unaffected:make_list("ge 5.1.32.120294"), vulnerable:make_list("lt 5.1.32.120294"))) flag++;
if (qpkg_check(package:"app-emulation/virtualbox-guest-additions", unaffected:make_list("ge 5.1.32"), vulnerable:make_list("lt 5.1.32"))) flag++;

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
