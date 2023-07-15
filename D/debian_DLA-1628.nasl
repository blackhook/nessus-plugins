#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-1628-2. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(120961);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/11");

  script_name(english:"Debian DLA-1628-2 : jasper regression update");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The update of jasper issued as DLA-1628-1 caused a regression due to
the fix for CVE-2018-19542, a NULL pointer dereference in the function
jp2_decode, which could lead to a denial of service. In some cases not
only invalid jp2 files but also valid jp2 files were rejected.

For Debian 8 'Jessie', this problem has been fixed in version
1.900.1-debian1-2.4+deb8u6.

We recommend that you upgrade your jasper packages.

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2019/04/msg00014.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/jessie/jasper"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade the affected packages.");
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libjasper-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libjasper-runtime");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libjasper1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:8.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/04/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/04/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/01/07");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2019-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"Debian Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/Debian/release", "Host/Debian/dpkg-l");

  exit(0);
}


include("audit.inc");
include("debian_package.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/Debian/release")) audit(AUDIT_OS_NOT, "Debian");
if (!get_kb_item("Host/Debian/dpkg-l")) audit(AUDIT_PACKAGE_LIST_MISSING);


flag = 0;
if (deb_check(release:"8.0", prefix:"libjasper-dev", reference:"1.900.1-debian1-2.4+deb8u6")) flag++;
if (deb_check(release:"8.0", prefix:"libjasper-runtime", reference:"1.900.1-debian1-2.4+deb8u6")) flag++;
if (deb_check(release:"8.0", prefix:"libjasper1", reference:"1.900.1-debian1-2.4+deb8u6")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
