#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 201206-25.
#
# The advisory text is Copyright (C) 2001-2016 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(59678);
  script_version("1.24");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/06");

  script_cve_id("CVE-2010-0408", "CVE-2010-0434", "CVE-2010-1452", "CVE-2010-2791", "CVE-2011-3192", "CVE-2011-3348", "CVE-2011-3368", "CVE-2011-3607", "CVE-2011-4317", "CVE-2012-0021", "CVE-2012-0031", "CVE-2012-0053", "CVE-2012-0883");
  script_bugtraq_id(38491, 38494, 38580, 41963, 42102, 49303, 49616, 49957, 50494, 50802, 51407, 51705, 51706, 53046);
  script_xref(name:"GLSA", value:"201206-25");

  script_name(english:"GLSA-201206-25 : Apache HTTP Server: Multiple vulnerabilities");
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
"The remote host is affected by the vulnerability described in GLSA-201206-25
(Apache HTTP Server: Multiple vulnerabilities)

    Multiple vulnerabilities have been discovered in Apache HTTP Server.
      Please review the CVE identifiers referenced below for details.
  
Impact :

    A remote attacker might obtain sensitive information, gain privileges,
      send requests to unintended servers behind proxies, bypass certain
      security restrictions, obtain the values of HTTPOnly cookies, or cause a
      Denial of Service in various ways.
    A local attacker could gain escalated privileges.
  
Workaround :

    There is no known workaround at this time."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/201206-25"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All Apache HTTP Server users should upgrade to the latest version:
      # emerge --sync
      # emerge --ask --oneshot --verbose '>=www-servers/apache-2.2.22-r1'"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_cwe_id(200);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:apache");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/06/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/06/25");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012-2021 Tenable Network Security, Inc.");
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

if (qpkg_check(package:"www-servers/apache", unaffected:make_list("ge 2.2.22-r1"), vulnerable:make_list("lt 2.2.22-r1"))) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "Apache HTTP Server");
}
