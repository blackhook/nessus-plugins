#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 201811-14.
#
# The advisory text is Copyright (C) 2001-2021 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(119134);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/02/12");

  script_cve_id("CVE-2017-17723", "CVE-2017-17724", "CVE-2018-10780", "CVE-2018-10958", "CVE-2018-10998", "CVE-2018-10999", "CVE-2018-11037", "CVE-2018-11531", "CVE-2018-12264", "CVE-2018-12265", "CVE-2018-5772", "CVE-2018-8976", "CVE-2018-8977", "CVE-2018-9144", "CVE-2018-9145", "CVE-2018-9146", "CVE-2018-9303", "CVE-2018-9304", "CVE-2018-9305", "CVE-2018-9306");
  script_xref(name:"GLSA", value:"201811-14");

  script_name(english:"GLSA-201811-14 : Exiv2: Multiple vulnerabilities");
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
"The remote host is affected by the vulnerability described in GLSA-201811-14
(Exiv2: Multiple vulnerabilities)

    Multiple vulnerabilities have been discovered in Exiv2. Please review
      the CVE identifiers referenced below for details.
  
Impact :

    A remote attacker could cause a Denial of Service condition or obtain
      sensitive information via a specially crafted file.
  
Workaround :

    There is no known workaround at this time."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/201811-14"
  );
  script_set_attribute(
    attribute:"solution",
    value:
"All Exiv2 users should upgrade to the latest version:
      # emerge --sync
      # emerge --ask --oneshot --verbose
      '>=media-gfx/exiv2-0.26_p20180811-r3'"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:exiv2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/01/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/11/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/11/26");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2018-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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

if (qpkg_check(package:"media-gfx/exiv2", unaffected:make_list("ge 0.26_p20180811-r3"), vulnerable:make_list("lt 0.26_p20180811-r3"))) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "Exiv2");
}
