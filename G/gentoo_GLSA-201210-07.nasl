#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 201210-07.
#
# The advisory text is Copyright (C) 2001-2019 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(62652);
  script_version("1.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/06");

  script_cve_id("CVE-2012-2859", "CVE-2012-2860", "CVE-2012-2865", "CVE-2012-2866", "CVE-2012-2867", "CVE-2012-2868", "CVE-2012-2869", "CVE-2012-2872", "CVE-2012-2874", "CVE-2012-2876", "CVE-2012-2877", "CVE-2012-2878", "CVE-2012-2879", "CVE-2012-2880", "CVE-2012-2881", "CVE-2012-2882", "CVE-2012-2883", "CVE-2012-2884", "CVE-2012-2885", "CVE-2012-2886", "CVE-2012-2887", "CVE-2012-2888", "CVE-2012-2889", "CVE-2012-2891", "CVE-2012-2892", "CVE-2012-2894", "CVE-2012-2896", "CVE-2012-2900", "CVE-2012-5108", "CVE-2012-5110", "CVE-2012-5111", "CVE-2012-5112", "CVE-2012-5376");
  script_bugtraq_id(54749, 55331, 55676, 55830, 55867);
  script_xref(name:"GLSA", value:"201210-07");

  script_name(english:"GLSA-201210-07 : Chromium: Multiple vulnerabilities");
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
"The remote host is affected by the vulnerability described in GLSA-201210-07
(Chromium: Multiple vulnerabilities)

    Multiple vulnerabilities have been discovered in Chromium. Please review
      the CVE identifiers and release notes referenced below for details.
  
Impact :

    A remote attacker could entice a user to open a specially crafted web
      site using Chromium, possibly resulting in the execution of arbitrary
      code with the privileges of the process, arbitrary file write, a Denial
      of Service condition, Cross-Site Scripting in SSL interstitial and
      various Universal Cross-Site Scripting attacks.
  
Workaround :

    There is no known workaround at this time."
  );
  # https://googlechromereleases.blogspot.com/2012/08/stable-channel-update_30.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?33992dc2"
  );
  # https://googlechromereleases.blogspot.com/2012/09/stable-channel-update_25.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?d441b099"
  );
  # https://googlechromereleases.blogspot.com/2012/10/stable-channel-update.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?e31d78d1"
  );
  # https://googlechromereleases.blogspot.com/2012/10/stable-channel-update_6105.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?359ba3a4"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/201210-07"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All Chromium users should upgrade to the latest version:
      # emerge --sync
      # emerge --ask --oneshot --verbose
      '>=www-client/chromium-22.0.1229.94'"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:chromium");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/08/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/10/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/10/22");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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

if (qpkg_check(package:"www-client/chromium", unaffected:make_list("ge 22.0.1229.94"), vulnerable:make_list("lt 22.0.1229.94"))) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "Chromium");
}
