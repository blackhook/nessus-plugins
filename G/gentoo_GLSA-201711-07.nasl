#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 201711-07.
#
# The advisory text is Copyright (C) 2001-2018 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(104515);
  script_version("3.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/11");

  script_cve_id("CVE-2017-11640", "CVE-2017-11724", "CVE-2017-12140", "CVE-2017-12418", "CVE-2017-12427", "CVE-2017-12691", "CVE-2017-12692", "CVE-2017-12693", "CVE-2017-12876", "CVE-2017-12877", "CVE-2017-12983", "CVE-2017-13058", "CVE-2017-13059", "CVE-2017-13060", "CVE-2017-13061", "CVE-2017-13062", "CVE-2017-13131", "CVE-2017-13132", "CVE-2017-13133", "CVE-2017-13134", "CVE-2017-13139", "CVE-2017-13140", "CVE-2017-13141", "CVE-2017-13142", "CVE-2017-13143", "CVE-2017-13144", "CVE-2017-13145", "CVE-2017-13146", "CVE-2017-13758", "CVE-2017-13768", "CVE-2017-13769", "CVE-2017-14060", "CVE-2017-14137", "CVE-2017-14138", "CVE-2017-14139", "CVE-2017-14172", "CVE-2017-14173", "CVE-2017-14174", "CVE-2017-14175", "CVE-2017-14224", "CVE-2017-14248", "CVE-2017-14249", "CVE-2017-15281");
  script_xref(name:"GLSA", value:"201711-07");

  script_name(english:"GLSA-201711-07 : ImageMagick: Multiple vulnerabilities");
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
"The remote host is affected by the vulnerability described in GLSA-201711-07
(ImageMagick: Multiple vulnerabilities)

    Multiple vulnerabilities have been discovered in ImageMagick. Please
      review the referenced CVE identifiers for details.
  
Impact :

    Remote attackers, by enticing a user to process a specially crafted
      file, could obtain sensitive information, cause a Denial of Service
      condition, or have other unspecified impacts.
  
Workaround :

    There is no known workaround at this time."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/201711-07"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All ImageMagick users should upgrade to the latest version:
      # emerge --sync
      # emerge --ask --oneshot --verbose '>=media-gfx/imagemagick-6.9.9.20'"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:imagemagick");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/11/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/11/13");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017-2021 Tenable Network Security, Inc.");
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

if (qpkg_check(package:"media-gfx/imagemagick", unaffected:make_list("ge 6.9.9.20"), vulnerable:make_list("lt 6.9.9.20"))) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "ImageMagick");
}
