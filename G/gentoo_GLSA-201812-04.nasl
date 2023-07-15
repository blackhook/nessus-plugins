#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 201812-04.
#
# The advisory text is Copyright (C) 2001-2019 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(119323);
  script_version("1.3");
  script_cvs_date("Date: 2019/04/30 14:30:16");

  script_cve_id("CVE-2018-4191", "CVE-2018-4197", "CVE-2018-4207", "CVE-2018-4208", "CVE-2018-4209", "CVE-2018-4210", "CVE-2018-4212", "CVE-2018-4213", "CVE-2018-4299", "CVE-2018-4306", "CVE-2018-4309", "CVE-2018-4311", "CVE-2018-4312", "CVE-2018-4314", "CVE-2018-4315", "CVE-2018-4316", "CVE-2018-4317", "CVE-2018-4318", "CVE-2018-4319", "CVE-2018-4323", "CVE-2018-4328", "CVE-2018-4358", "CVE-2018-4359", "CVE-2018-4361");
  script_xref(name:"GLSA", value:"201812-04");

  script_name(english:"GLSA-201812-04 : WebkitGTK+: Multiple vulnerabilities");
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
"The remote host is affected by the vulnerability described in GLSA-201812-04
(WebkitGTK+: Multiple vulnerabilities)

    Multiple vulnerabilities have been discovered in WebKitGTK+. Please
      review the referenced CVE identifiers for details.
  
Impact :

    A remote attacker could execute arbitrary commands or cause a Denial of
      Service condition via maliciously crafted web content.
  
Workaround :

    There is no known workaround at this time."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/201812-04"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All WebkitGTK+ users should upgrade to the latest version:
      # emerge --sync
      # emerge --ask --oneshot --verbose '>=net-libs/webkit-gtk-2.22.0'"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:webkit-gtk");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2018/12/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/12/03");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2018-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");
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

if (qpkg_check(package:"net-libs/webkit-gtk", unaffected:make_list("ge 2.22.0"), vulnerable:make_list("lt 2.22.0"))) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "WebkitGTK+");
}
