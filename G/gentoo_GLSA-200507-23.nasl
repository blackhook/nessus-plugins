#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 200507-23.
#
# The advisory text is Copyright (C) 2001-2018 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(19325);
  script_version("1.18");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/06");

  script_cve_id("CVE-2005-1852");
  script_bugtraq_id(14345);
  script_xref(name:"GLSA", value:"200507-23");

  script_name(english:"GLSA-200507-23 : Kopete: Vulnerability in included Gadu library");
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
"The remote host is affected by the vulnerability described in GLSA-200507-23
(Kopete: Vulnerability in included Gadu library)

    Kopete contains an internal copy of libgadu and is therefore
    subject to several input validation vulnerabilities in libgadu.
  
Impact :

    A remote attacker could exploit this vulnerability to execute
    arbitrary code or crash Kopete.
  
Workaround :

    Delete all Gadu Gadu contacts."
  );
  # http://www.kde.org/info/security/advisory-20050721-1.txt
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.kde.org/info/security/advisory-20050721-1.txt"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/200507-23"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All Kopete users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose kde-base/kdenetwork
    All KDE Split Ebuild Kopete users should upgrade to the latest
    version:
    # emerge --sync
    # emerge --ask --oneshot --verbose '>=kde-base/kopete-3.4.1-r1'"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:kdenetwork");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:kopete");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2005/07/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2005/07/31");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2005-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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

if (qpkg_check(package:"kde-base/kdenetwork", unaffected:make_list("ge 3.4.1-r1", "rge 3.3.2-r2"), vulnerable:make_list("lt 3.4.1-r1"))) flag++;
if (qpkg_check(package:"kde-base/kopete", unaffected:make_list("ge 3.4.1-r1"), vulnerable:make_list("lt 3.4.1-r1"))) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "Kopete");
}
