#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 202104-10.
#
# The advisory text is Copyright (C) 2001-2021 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include('deprecated_nasl_level.inc');
include("compat.inc");

if (description)
{
  script_id(149233);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/05/05");

  script_cve_id("CVE-2021-23961", "CVE-2021-23968", "CVE-2021-23969", "CVE-2021-23970", "CVE-2021-23971", "CVE-2021-23972", "CVE-2021-23973", "CVE-2021-23974", "CVE-2021-23975", "CVE-2021-23976", "CVE-2021-23977", "CVE-2021-23978", "CVE-2021-23981", "CVE-2021-23982", "CVE-2021-23983", "CVE-2021-23984", "CVE-2021-23985", "CVE-2021-23986", "CVE-2021-23987", "CVE-2021-23988", "CVE-2021-23994", "CVE-2021-23995", "CVE-2021-23998", "CVE-2021-23999", "CVE-2021-24002", "CVE-2021-29945", "CVE-2021-29946");
  script_xref(name:"GLSA", value:"202104-10");

  script_name(english:"GLSA-202104-10 : Mozilla Firefox: Multiple vulnerabilities");
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
"The remote host is affected by the vulnerability described in GLSA-202104-10
(Mozilla Firefox: Multiple vulnerabilities)

    Multiple vulnerabilities have been discovered in Mozilla Firefox. Please
      review the CVE identifiers referenced below for details.
  
Impact :

    Please review the referenced CVE identifiers for details.
  
Workaround :

    There is no known workaround at this time."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.mozilla.org/en-US/security/advisories/mfsa2021-08/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.mozilla.org/en-US/security/advisories/mfsa2021-11/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.mozilla.org/en-US/security/advisories/mfsa2021-15/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/202104-10"
  );
  script_set_attribute(
    attribute:"solution",
    value:
"All Mozilla Firefox ESR users should upgrade to the latest version:
      # emerge --sync
      # emerge --ask --oneshot --verbose '>=www-client/firefox-78.10.0'
    All Mozilla Firefox ESR binary users should upgrade to the latest
      version:
      # emerge --sync
      # emerge --ask --oneshot --verbose '>=www-client/firefox-bin-78.10.0'
    All Mozilla Firefox users should upgrade to the latest version:
      # emerge --sync
      # emerge --ask --oneshot --verbose '>=www-client/firefox-88.0'
    All Mozilla Firefox binary users should upgrade to the latest version:
      # emerge --sync
      # emerge --ask --oneshot --verbose '>=www-client/firefox-bin-88.0'"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:firefox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:firefox-bin");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/02/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/04/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/05/03");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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

if (qpkg_check(package:"www-client/firefox", unaffected:make_list("ge 78.10.0", "ge 88.0"), vulnerable:make_list("lt 88.0"))) flag++;
if (qpkg_check(package:"www-client/firefox-bin", unaffected:make_list("ge 78.10.0", "ge 88.0"), vulnerable:make_list("lt 88.0"))) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "Mozilla Firefox");
}
