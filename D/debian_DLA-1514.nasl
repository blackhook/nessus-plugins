#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-1514-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(117641);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/11");

  script_name(english:"Debian DLA-1514-1 : texlive-bin security update");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Nick Roessler from the University of Pennsylvania has found a buffer
overflow in texlive-bin, the executables for TexLive, the popular
distribution of TeX document production system.

This buffer overflow can be used for arbitrary code execution by
crafting a special type1 font (.pfb) and provide it to users running
pdf(la)tex, dvips or luatex in a way that the font is loaded.

For Debian 8 'Jessie', this problem has been fixed in version
2014.20140926.35254-6+deb8u1.

We recommend that you upgrade your texlive-bin packages.

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2018/09/msg00025.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/jessie/texlive-bin"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade the affected packages.");
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libkpathsea-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libkpathsea6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libptexenc-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libptexenc1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libsynctex-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libsynctex1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:luatex");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:texlive-binaries");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:8.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2018/09/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/09/24");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2018-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (deb_check(release:"8.0", prefix:"libkpathsea-dev", reference:"2014.20140926.35254-6+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libkpathsea6", reference:"2014.20140926.35254-6+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libptexenc-dev", reference:"2014.20140926.35254-6+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libptexenc1", reference:"2014.20140926.35254-6+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libsynctex-dev", reference:"2014.20140926.35254-6+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libsynctex1", reference:"2014.20140926.35254-6+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"luatex", reference:"2014.20140926.35254-6+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"texlive-binaries", reference:"2014.20140926.35254-6+deb8u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
