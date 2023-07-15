#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 201810-04.
#
# The advisory text is Copyright (C) 2001-2018 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(117969);
  script_version("1.1");
  script_cvs_date("Date: 2018/10/09 17:56:08");

  script_xref(name:"CERT", value:"332928");
  script_xref(name:"GLSA", value:"201810-04");

  script_name(english:"GLSA-201810-04 : ImageMagick: Security hardening");
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
"The remote host is affected by the vulnerability described in GLSA-201810-04
(ImageMagick: Security hardening)

    If you process an image with ImageMagick and don&rsquo;t validate the file
      before (e.g. check magic byte), ImageMagick will call any coders found in
      the given file. So if ImageMagick will find Ghostscript for example, it
      will call Ghostscript.
    Due to multiple -dSAFER sandbox bypass vulnerabilities in Ghostscript,
      this can lead to arbitrary code execution.
    To mitigate this problem we install a policy.xml file by default which
      will disable PS, EPS, PDF, and XPS coders.
  
Impact :

    A remote attacker, by enticing a user to process a specially crafted
      image file, could execute arbitrary code with the privileges of the
      process or cause a Denial of Service condition.
  
Workaround :

    There is no known workaround at this time."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/201810-04"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All ImageMagick 6 users should upgrade to the latest version:
      # emerge --sync
      # emerge --ask --oneshot --verbose
      '>=media-gfx/imagemagick-6.9.10.10-r1'
    All ImageMagick 7 users should upgrade to the latest version:
      # emerge --sync
      # emerge --ask --oneshot --verbose
      '>=media-gfx/imagemagick-7.0.8.10-r1'"
  );
  script_set_attribute(attribute:"risk_factor", value:"Medium");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:imagemagick");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2018/10/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/10/09");
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

if (qpkg_check(package:"media-gfx/imagemagick", unaffected:make_list("ge 6.9.10.10-r1", "ge 7.0.8.10-r1"), vulnerable:make_list("lt 6.9.10.10-r1", "lt 7.0.8.10-r1"))) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "ImageMagick");
}
