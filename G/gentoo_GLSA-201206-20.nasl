#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 201206-20.
#
# The advisory text is Copyright (C) 2001-2016 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(59673);
  script_version("1.12");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/06");

  script_cve_id("CVE-2011-2485", "CVE-2012-2370");
  script_bugtraq_id(48425, 53548);
  script_xref(name:"GLSA", value:"201206-20");

  script_name(english:"GLSA-201206-20 : gdk-pixbuf: Denial of Service");
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
"The remote host is affected by the vulnerability described in GLSA-201206-20
(gdk-pixbuf: Denial of Service)

    Two vulnerabilities have been found in gdk-pixbuf:
      The 'gdk_pixbuf__gif_image_load()' function in io-gif.c fails to
        properly handle certain return values from subroutines (CVE-2011-2485).
      The 'read_bitmap_file_data()' function in io-xbm.c contains an
        integer overflow error (CVE-2012-2370).
  
Impact :

    A remote attacker could entice a user to open a specially crafted image
      in an application linked against gdk-pixbuf, possibly resulting in Denial
      of Service.
  
Workaround :

    There is no known workaround at this time."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/201206-20"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All gdk-pixbuf users should upgrade to the latest version:
      # emerge --sync
      # emerge --ask --oneshot --verbose '>=x11-libs/gdk-pixbuf-2.24.1-r1'
    Packages which depend on this library may need to be recompiled. Tools
      such as revdep-rebuild may assist in identifying some of these packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:gdk-pixbuf");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/06/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/06/25");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012-2021 Tenable Network Security, Inc.");
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

if (qpkg_check(package:"x11-libs/gdk-pixbuf", unaffected:make_list("ge 2.24.1-r1"), vulnerable:make_list("lt 2.24.1-r1"))) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "gdk-pixbuf");
}
