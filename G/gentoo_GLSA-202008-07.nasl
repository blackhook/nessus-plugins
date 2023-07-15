#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 202008-07.
#
# The advisory text is Copyright (C) 2001-2022 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(161692);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/06/02");

  script_cve_id("CVE-2020-6542", "CVE-2020-6543", "CVE-2020-6544", "CVE-2020-6545", "CVE-2020-6547", "CVE-2020-6548", "CVE-2020-6549", "CVE-2020-6550", "CVE-2020-6551", "CVE-2020-6552", "CVE-2020-6553", "CVE-2020-6554", "CVE-2020-6555");
  script_xref(name:"GLSA", value:"202008-07");

  script_name(english:"GLSA-202008-07 : Chromium, Google Chrome: Multiple vulnerabilities");
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
"The remote host is affected by the vulnerability described in GLSA-202008-07
(Chromium, Google Chrome: Multiple vulnerabilities)

    Multiple vulnerabilities have been discovered in Chromium and Google
      Chrome. Please review the CVE identifiers referenced below for details.
  
Impact :

    Please review the referenced CVE identifiers for details.
  
Workaround :

    There is no known workaround at this time."
  );
  # https://chromereleases.googleblog.com/2020/07/stable-channel-update-for-desktop_27.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?356bbf62"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/202008-07"
  );
  script_set_attribute(
    attribute:"solution",
    value:
"All Chromium users should upgrade to the latest version:
      # emerge --sync
      # emerge --ask --oneshot --verbose
      '>=www-client/chromium-84.0.4147.125'
    All Google Chrome users should upgrade to the latest version:
      # emerge --sync
      # emerge --ask --oneshot --verbose
      '>=www-client/google-chrome-84.0.4147.125'"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-6553");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:chromium");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:google-chrome");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/09/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/08/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/05/31");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");
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

if (qpkg_check(package:"www-client/chromium", unaffected:make_list("ge 84.0.4147.125"), vulnerable:make_list("lt 84.0.4147.125"))) flag++;
if (qpkg_check(package:"www-client/google-chrome", unaffected:make_list("ge 84.0.4147.125"), vulnerable:make_list("lt 84.0.4147.125"))) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "Chromium / Google Chrome");
}
