#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 201808-01.
#
# The advisory text is Copyright (C) 2001-2019 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(112075);
  script_version("1.4");
  script_cvs_date("Date: 2019/02/06 11:41:39");

  script_cve_id("CVE-2018-4117", "CVE-2018-6044", "CVE-2018-6150", "CVE-2018-6151", "CVE-2018-6152", "CVE-2018-6153", "CVE-2018-6154", "CVE-2018-6155", "CVE-2018-6156", "CVE-2018-6157", "CVE-2018-6158", "CVE-2018-6159", "CVE-2018-6160", "CVE-2018-6161", "CVE-2018-6162", "CVE-2018-6163", "CVE-2018-6164", "CVE-2018-6165", "CVE-2018-6166", "CVE-2018-6167", "CVE-2018-6168", "CVE-2018-6169", "CVE-2018-6170", "CVE-2018-6171", "CVE-2018-6172", "CVE-2018-6173", "CVE-2018-6174", "CVE-2018-6175", "CVE-2018-6176", "CVE-2018-6177", "CVE-2018-6178", "CVE-2018-6179");
  script_xref(name:"GLSA", value:"201808-01");

  script_name(english:"GLSA-201808-01 : Chromium, Google Chrome: Multiple vulnerabilities");
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
"The remote host is affected by the vulnerability described in GLSA-201808-01
(Chromium, Google Chrome: Multiple vulnerabilities)

    Multiple vulnerabilities have been discovered in Chromium and Google
      Chrome. Please review the referenced CVE identifiers and Google Chrome
      Releases for details.
  
Impact :

    A remote attacker could escalate privileges, cause a heap buffer
      overflow, obtain sensitive information or spoof a URL.
  
Workaround :

    There is no known workaround at this time."
  );
  # https://chromereleases.googleblog.com/2018/07/stable-channel-update-for-desktop.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?89d1144b"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/201808-01"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All Chromium users should upgrade to the latest version:
      # emerge --sync
      # emerge --ask --oneshot --verbose
      '>=www-client/chromium-68.0.3440.75'
    All Google Chrome users should upgrade to the latest version:
      # emerge --sync
      # emerge --ask --oneshot --verbose
      '>=www-client/google-chrome-68.0.3440.75'"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:chromium");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:google-chrome");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/04/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/08/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/08/23");
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

if (qpkg_check(package:"www-client/chromium", unaffected:make_list("ge 68.0.3440.75"), vulnerable:make_list("lt 68.0.3440.75"))) flag++;
if (qpkg_check(package:"www-client/google-chrome", unaffected:make_list("ge 68.0.3440.75"), vulnerable:make_list("lt 68.0.3440.75"))) flag++;

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
