#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 201403-01.
#
# The advisory text is Copyright (C) 2001-2018 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(72851);
  script_version("1.18");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/06");

  script_cve_id("CVE-2013-2906", "CVE-2013-2907", "CVE-2013-2908", "CVE-2013-2909", "CVE-2013-2910", "CVE-2013-2911", "CVE-2013-2912", "CVE-2013-2913", "CVE-2013-2915", "CVE-2013-2916", "CVE-2013-2917", "CVE-2013-2918", "CVE-2013-2919", "CVE-2013-2920", "CVE-2013-2921", "CVE-2013-2922", "CVE-2013-2923", "CVE-2013-2925", "CVE-2013-2926", "CVE-2013-2927", "CVE-2013-2928", "CVE-2013-2931", "CVE-2013-6621", "CVE-2013-6622", "CVE-2013-6623", "CVE-2013-6624", "CVE-2013-6625", "CVE-2013-6626", "CVE-2013-6627", "CVE-2013-6628", "CVE-2013-6632", "CVE-2013-6634", "CVE-2013-6635", "CVE-2013-6636", "CVE-2013-6637", "CVE-2013-6638", "CVE-2013-6639", "CVE-2013-6640", "CVE-2013-6641", "CVE-2013-6643", "CVE-2013-6644", "CVE-2013-6645", "CVE-2013-6646", "CVE-2013-6649", "CVE-2013-6650", "CVE-2013-6652", "CVE-2013-6653", "CVE-2013-6654", "CVE-2013-6655", "CVE-2013-6656", "CVE-2013-6657", "CVE-2013-6658", "CVE-2013-6659", "CVE-2013-6660", "CVE-2013-6661", "CVE-2013-6663", "CVE-2013-6664", "CVE-2013-6665", "CVE-2013-6666", "CVE-2013-6667", "CVE-2013-6668", "CVE-2013-6802", "CVE-2014-1681");
  script_bugtraq_id(62752, 63024, 63025, 63026, 63028, 63667, 63669, 63670, 63671, 63672, 63674, 63675, 63677, 63678, 63727, 63729, 64078, 64354, 64805, 64981, 65168, 65172, 65232, 65699, 65779, 65930);
  script_xref(name:"GLSA", value:"201403-01");

  script_name(english:"GLSA-201403-01 : Chromium, V8: Multiple vulnerabilities");
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
"The remote host is affected by the vulnerability described in GLSA-201403-01
(Chromium, V8: Multiple vulnerabilities)

    Multiple vulnerabilities have been discovered in Chromium and V8. Please
      review the CVE identifiers and release notes referenced below for
      details.
  
Impact :

    A context-dependent attacker could entice a user to open a specially
      crafted website or JavaScript program using Chromium or V8, possibly
      resulting in the execution of arbitrary code with the privileges of the
      process or a Denial of Service condition. Furthermore, a remote attacker
      may be able to bypass security restrictions or have other unspecified
      impact.
  
Workaround :

    There is no known workaround at this time."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/201403-01"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All chromium users should upgrade to the latest version:
      # emerge --sync
      # emerge --ask --oneshot --verbose
      '>=www-client/chromium-33.0.1750.146'
    Gentoo has discontinued support for separate V8 package. We recommend
      that users unmerge V8:
      # emerge --unmerge 'dev-lang/v8'"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:chromium");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:v8");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/03/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/03/06");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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

if (qpkg_check(package:"www-client/chromium", unaffected:make_list("ge 33.0.1750.146"), vulnerable:make_list("lt 33.0.1750.146"))) flag++;
if (qpkg_check(package:"dev-lang/v8", unaffected:make_list(), vulnerable:make_list("lt 3.20.17.13"))) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "Chromium / V8");
}
