#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-2057-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(132681);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/11");

  script_name(english:"Debian DLA-2057-1 : pillow security update");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"It was discovered that there were three vulnerabilities in Pillow, an
imaging library for the Python programming language :

  - CVE-2019-19911: Prevent a denial of service
    vulnerability caused by FpxImagePlugin.py calling the
    range function on an unvalidated 32-bit integer if the
    number of bands is large.

  - CVE-2020-5312: PCX 'P mode' buffer overflow.

  - CVE-2020-5313: FLI buffer overflow.

For Debian 8 'Jessie', these issues have been fixed in pillow version
2.6.1-2+deb8u4.

We recommend that you upgrade your pillow packages.

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2020/01/msg00003.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/jessie/pillow"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade the affected packages.");
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:python-imaging");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:python-imaging-tk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:python-pil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:python-pil-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:python-pil-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:python-pil.imagetk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:python-pil.imagetk-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:python-sane");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:python-sane-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:python3-pil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:python3-pil-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:python3-pil.imagetk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:python3-pil.imagetk-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:python3-sane");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:python3-sane-dbg");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:8.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/01/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/01/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/01/07");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2020-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (deb_check(release:"8.0", prefix:"python-imaging", reference:"2.6.1-2+deb8u4")) flag++;
if (deb_check(release:"8.0", prefix:"python-imaging-tk", reference:"2.6.1-2+deb8u4")) flag++;
if (deb_check(release:"8.0", prefix:"python-pil", reference:"2.6.1-2+deb8u4")) flag++;
if (deb_check(release:"8.0", prefix:"python-pil-dbg", reference:"2.6.1-2+deb8u4")) flag++;
if (deb_check(release:"8.0", prefix:"python-pil-doc", reference:"2.6.1-2+deb8u4")) flag++;
if (deb_check(release:"8.0", prefix:"python-pil.imagetk", reference:"2.6.1-2+deb8u4")) flag++;
if (deb_check(release:"8.0", prefix:"python-pil.imagetk-dbg", reference:"2.6.1-2+deb8u4")) flag++;
if (deb_check(release:"8.0", prefix:"python-sane", reference:"2.6.1-2+deb8u4")) flag++;
if (deb_check(release:"8.0", prefix:"python-sane-dbg", reference:"2.6.1-2+deb8u4")) flag++;
if (deb_check(release:"8.0", prefix:"python3-pil", reference:"2.6.1-2+deb8u4")) flag++;
if (deb_check(release:"8.0", prefix:"python3-pil-dbg", reference:"2.6.1-2+deb8u4")) flag++;
if (deb_check(release:"8.0", prefix:"python3-pil.imagetk", reference:"2.6.1-2+deb8u4")) flag++;
if (deb_check(release:"8.0", prefix:"python3-pil.imagetk-dbg", reference:"2.6.1-2+deb8u4")) flag++;
if (deb_check(release:"8.0", prefix:"python3-sane", reference:"2.6.1-2+deb8u4")) flag++;
if (deb_check(release:"8.0", prefix:"python3-sane-dbg", reference:"2.6.1-2+deb8u4")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
