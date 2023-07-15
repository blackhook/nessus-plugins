#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 201803-14.
#
# The advisory text is Copyright (C) 2001-2020 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(108820);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/09/28");

  script_cve_id("CVE-2017-7753", "CVE-2017-7779", "CVE-2017-7784", "CVE-2017-7785", "CVE-2017-7786", "CVE-2017-7787", "CVE-2017-7791", "CVE-2017-7792", "CVE-2017-7793", "CVE-2017-7800", "CVE-2017-7801", "CVE-2017-7802", "CVE-2017-7803", "CVE-2017-7805", "CVE-2017-7807", "CVE-2017-7809", "CVE-2017-7810", "CVE-2017-7814", "CVE-2017-7818", "CVE-2017-7819", "CVE-2017-7823", "CVE-2017-7824", "CVE-2017-7825", "CVE-2017-7826", "CVE-2017-7828", "CVE-2017-7829", "CVE-2017-7830", "CVE-2017-7846", "CVE-2017-7847", "CVE-2017-7848", "CVE-2018-5089", "CVE-2018-5095", "CVE-2018-5096", "CVE-2018-5097", "CVE-2018-5098", "CVE-2018-5099", "CVE-2018-5102", "CVE-2018-5103", "CVE-2018-5104", "CVE-2018-5117");
  script_xref(name:"GLSA", value:"201803-14");

  script_name(english:"GLSA-201803-14 : Mozilla Thunderbird: Multiple vulnerabilities");
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
"The remote host is affected by the vulnerability described in GLSA-201803-14
(Mozilla Thunderbird: Multiple vulnerabilities)

    Multiple vulnerabilities have been discovered in Mozilla Thunderbird.
      Please review the referenced Mozilla Foundation Security Advisories and
      CVE identifiers below for details.
  
Impact :

    A remote attacker may be able to execute arbitrary code, cause a Denial
      of Service condition, obtain sensitive information, conduct URL
      hijacking, or conduct cross-site scripting (XSS).
  
Workaround :

    There is no known workaround at this time."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.mozilla.org/en-US/security/advisories/mfsa2017-20/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.mozilla.org/en-US/security/advisories/mfsa2017-23/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.mozilla.org/en-US/security/advisories/mfsa2017-26/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.mozilla.org/en-US/security/advisories/mfsa2017-30/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.mozilla.org/en-US/security/advisories/mfsa2018-04/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/201803-14"
  );
  script_set_attribute(
    attribute:"solution",
    value:
"All Thunderbird users should upgrade to the latest version:
      # emerge --sync
      # emerge --ask --oneshot --verbose '>=mail-client/thunderbird-52.6.0'
    All Thunderbird binary users should upgrade to the latest version:
      # emerge --sync
      # emerge --ask --oneshot --verbose
      '>=mail-client/thunderbird-bin-52.6.0'"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:thunderbird");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:thunderbird-bin");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/06/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/03/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/04/04");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2018-2020 and is owned by Tenable, Inc. or an Affiliate thereof.");
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

if (qpkg_check(package:"mail-client/thunderbird", unaffected:make_list("ge 52.6.0"), vulnerable:make_list("lt 52.6.0"))) flag++;
if (qpkg_check(package:"mail-client/thunderbird-bin", unaffected:make_list("ge 52.6.0"), vulnerable:make_list("lt 52.6.0"))) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "Mozilla Thunderbird");
}
