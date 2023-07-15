#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 201903-06.
#
# The advisory text is Copyright (C) 2001-2020 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(122734);
  script_version("1.2");
  script_cvs_date("Date: 2020/02/05");

  script_cve_id("CVE-2018-20174", "CVE-2018-20175", "CVE-2018-20176", "CVE-2018-20177", "CVE-2018-20178", "CVE-2018-20179", "CVE-2018-20180", "CVE-2018-20181", "CVE-2018-20182", "CVE-2018-8791", "CVE-2018-8792", "CVE-2018-8793", "CVE-2018-8794", "CVE-2018-8795", "CVE-2018-8796", "CVE-2018-8797", "CVE-2018-8798", "CVE-2018-8799", "CVE-2018-8800");
  script_xref(name:"GLSA", value:"201903-06");

  script_name(english:"GLSA-201903-06 : rdesktop: Multiple vulnerabilities");
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
"The remote host is affected by the vulnerability described in GLSA-201903-06
(rdesktop: Multiple vulnerabilities)

    Multiple vulnerabilities have been discovered in rdesktop. Please review
      the CVE identifiers referenced below for details.
  
Impact :

    A remote attacker could cause a Denial of Service condition, obtain
      sensitive information, or execute arbitrary code.
  
Workaround :

    There is no known workaround at this time."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/201903-06"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All rdesktop users should upgrade to the latest version:
      # emerge --sync
      # emerge --ask --oneshot --verbose '>=net-misc/rdesktop-1.8.4'"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:rdesktop");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/02/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/03/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/03/11");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2019-2020 and is owned by Tenable, Inc. or an Affiliate thereof.");
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

if (qpkg_check(package:"net-misc/rdesktop", unaffected:make_list("ge 1.8.4"), vulnerable:make_list("lt 1.8.4"))) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "rdesktop");
}
