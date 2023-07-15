#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 201801-03.
#
# The advisory text is Copyright (C) 2001-2018 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(105629);
  script_version("3.6");
  script_cvs_date("Date: 2018/10/25 11:32:02");

  script_cve_id("CVE-2017-15407", "CVE-2017-15408", "CVE-2017-15409", "CVE-2017-15410", "CVE-2017-15411", "CVE-2017-15412", "CVE-2017-15413", "CVE-2017-15415", "CVE-2017-15416", "CVE-2017-15417", "CVE-2017-15418", "CVE-2017-15419", "CVE-2017-15420", "CVE-2017-15422", "CVE-2017-15423", "CVE-2017-15424", "CVE-2017-15425", "CVE-2017-15426", "CVE-2017-15427", "CVE-2017-15429");
  script_xref(name:"GLSA", value:"201801-03");

  script_name(english:"GLSA-201801-03 : Chromium, Google Chrome: Multiple vulnerabilities");
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
"The remote host is affected by the vulnerability described in GLSA-201801-03
(Chromium, Google Chrome: Multiple vulnerabilities)

    Multiple vulnerabilities have been discovered in Chromium and Google
      Chrome. Please review the CVE identifiers referenced below for details.
  
Impact :

    A remote attacker could possibly execute arbitrary code with the
      privileges of the process, cause a Denial of Service condition, bypass
      content security controls, or conduct URL spoofing.
  
Workaround :

    There are no known workarounds at this time."
  );
  # https://chromereleases.googleblog.com/2017/12/stable-channel-update-for-desktop.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?98a7b4bd"
  );
  # https://chromereleases.googleblog.com/2017/12/stable-channel-update-for-desktop_14.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?125c6f30"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/201801-03"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All Chromium users should upgrade to the latest version:
      # emerge --sync
      # emerge --ask --oneshot --verbose
      '>=www-client/chromium-63.0.3239.108'
    All Google Chrome users should upgrade to the latest version:
      # emerge --sync
      # emerge --ask --oneshot --verbose
      '>=www-client/google-chrome-63.0.3239.108'"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:chromium");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:google-chrome");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2018/01/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/01/08");
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

if (qpkg_check(package:"www-client/chromium", unaffected:make_list("ge 63.0.3239.108"), vulnerable:make_list("lt 63.0.3239.108"))) flag++;
if (qpkg_check(package:"www-client/google-chrome", unaffected:make_list("ge 63.0.3239.108"), vulnerable:make_list("lt 63.0.3239.108"))) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "Chromium / Google Chrome");
}
