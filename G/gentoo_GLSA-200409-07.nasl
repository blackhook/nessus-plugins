#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 200409-07.
#
# The advisory text is Copyright (C) 2001-2018 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(14661);
  script_version("1.20");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/06");

  script_cve_id("CVE-2004-0802");
  script_xref(name:"GLSA", value:"200409-07");

  script_name(english:"GLSA-200409-07 : xv: Buffer overflows in image handling");
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
"The remote host is affected by the vulnerability described in GLSA-200409-07
(xv: Buffer overflows in image handling)

    Multiple buffer overflow and integer handling vulnerabilities have been
    discovered in xv's image processing code. These vulnerabilities have been
    found in the xvbmp.c, xviris.c, xvpcx.c and xvpm.c source files.
  
Impact :

    An attacker might be able to embed malicious code into an image, which
    would lead to the execution of arbitrary code under the privileges of the
    user viewing the image.
  
Workaround :

    There is no known workaround at this time."
  );
  # http://www.securityfocus.com/archive/1/372345/2004-08-15/2004-08-21/0
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.securityfocus.com/archive/1/372345/2004-08-15/2004-08-21/0"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/200409-07"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All xv users should upgrade to the latest stable version:
    # emerge sync
    # emerge -pv '>=media-gfx/xv-3.10a-r7'
    # emerge '>=media-gfx/xv-3.10a-r7'"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:xv");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2004/09/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2004/09/03");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2004-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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

if (qpkg_check(package:"media-gfx/xv", unaffected:make_list("ge 3.10a-r7"), vulnerable:make_list("lt 3.10a-r7"))) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "xv");
}
