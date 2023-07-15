#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 201710-14.
#
# The advisory text is Copyright (C) 2001-2018 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(103849);
  script_version("3.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/11");

  script_cve_id("CVE-2017-7006", "CVE-2017-7011", "CVE-2017-7012", "CVE-2017-7018", "CVE-2017-7019", "CVE-2017-7020", "CVE-2017-7030", "CVE-2017-7034", "CVE-2017-7037", "CVE-2017-7038", "CVE-2017-7039", "CVE-2017-7040", "CVE-2017-7041", "CVE-2017-7042", "CVE-2017-7043");
  script_xref(name:"GLSA", value:"201710-14");

  script_name(english:"GLSA-201710-14 : WebKitGTK+: Multiple Vulnerabilities");
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
"The remote host is affected by the vulnerability described in GLSA-201710-14
(WebKitGTK+: Multiple Vulnerabilities)

    Multiple vulnerabilities have been discovered in WebkitGTK+. Please
      review the references below for details.
  
Impact :

    A remote attacker could execute arbitrary code, cause a Denial of
      Service condition, bypass intended memory-read restrictions, conduct a
      timing side-channel attack to bypass the Same Origin Policy, obtain
      sensitive information, or spoof the address bar.
  
Workaround :

    There is no known workaround at this time."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/201710-14"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All WebKitGTK+ users should upgrade to the latest version:
      # emerge --sync
      # emerge --ask --oneshot --verbose '>=net-libs/webkit-gtk-2.16.6'
    Packages which depend on this library may need to be recompiled. Tools
      such as revdep-rebuild may assist in identifying some of these packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:webkit-gtk");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/10/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/10/16");
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

if (qpkg_check(package:"net-libs/webkit-gtk", unaffected:make_list("ge 2.16.6"), vulnerable:make_list("lt 2.16.6"))) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "WebKitGTK+");
}
