#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 201802-02.
#
# The advisory text is Copyright (C) 2001-2018 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(106883);
  script_version("3.4");
  script_cvs_date("Date: 2018/11/16 15:19:25");

  script_cve_id("CVE-2018-6031", "CVE-2018-6032", "CVE-2018-6033", "CVE-2018-6034", "CVE-2018-6035", "CVE-2018-6036", "CVE-2018-6037", "CVE-2018-6038", "CVE-2018-6039", "CVE-2018-6040", "CVE-2018-6041", "CVE-2018-6042", "CVE-2018-6043", "CVE-2018-6045", "CVE-2018-6046", "CVE-2018-6047", "CVE-2018-6048", "CVE-2018-6049", "CVE-2018-6050", "CVE-2018-6051", "CVE-2018-6052", "CVE-2018-6053", "CVE-2018-6054", "CVE-2018-6056");
  script_xref(name:"GLSA", value:"201802-02");

  script_name(english:"GLSA-201802-02 : Chromium, Google Chrome: Multiple vulnerabilities");
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
"The remote host is affected by the vulnerability described in GLSA-201802-02
(Chromium, Google Chrome: Multiple vulnerabilities)

    Multiple vulnerabilities have been discovered in Chromium and Google
      Chrome. Please review the referenced CVE identifiers and Google Chrome
      Releases for details.
  
Impact :

    A remote attacker could possibly execute arbitrary code with the
      privileges of the process, cause a Denial of Service condition, bypass
      content security controls, or conduct URL spoofing.
  
Workaround :

    There is no known workaround at this time."
  );
  # https://chromereleases.googleblog.com/2018/01/stable-channel-update-for-desktop_24.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?26e44d0b"
  );
  # https://chromereleases.googleblog.com/2018/02/stable-channel-update-for-desktop_13.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?7f96d3ea"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/201802-02"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All Chromium users should upgrade to the latest version:
      # emerge --sync
      # emerge --ask --oneshot --verbose
      '>=www-client/chromium-64.0.3282.167'
    All Google Chrome users should upgrade to the latest version:
      # emerge --sync
      # emerge --ask --oneshot --verbose
      '>=www-client/google-chrome-64.0.3282.167'"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:chromium");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:google-chrome");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2018/02/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/02/20");
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

if (qpkg_check(package:"www-client/chromium", unaffected:make_list("ge 64.0.3282.167"), vulnerable:make_list("lt 64.0.3282.167"))) flag++;
if (qpkg_check(package:"www-client/google-chrome", unaffected:make_list("ge 64.0.3282.167"), vulnerable:make_list("lt 64.0.3282.167"))) flag++;

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
