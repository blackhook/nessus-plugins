#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-2523-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(144925);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/15");

  script_cve_id("CVE-2017-14528", "CVE-2020-19667", "CVE-2020-25665", "CVE-2020-25674", "CVE-2020-27560", "CVE-2020-27750", "CVE-2020-27760", "CVE-2020-27763", "CVE-2020-27765", "CVE-2020-27773", "CVE-2020-29599");
  script_xref(name:"IAVB", value:"2020-B-0042-S");

  script_name(english:"Debian DLA-2523-1 : imagemagick security update");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"Several security vulnerabilities were found in ImageMagick, a suite of
image manipulation programs. An attacker could cause denial of service
and execution of arbitrary code when a crafted image file is
processed.

CVE-2017-14528

The TIFFSetProfiles function in coders/tiff.c has incorrect
expectations about whether LibTIFF TIFFGetField return values imply
that data validation has occurred, which allows remote attackers to
cause a denial of service (use-after-free after an invalid call to
TIFFSetField, and application crash) via a crafted file.

CVE-2020-19667

Stack-based buffer overflow and unconditional jump in ReadXPMImage in
coders/xpm.c

CVE-2020-25665

The PALM image coder at coders/palm.c makes an improper call to
AcquireQuantumMemory() in routine WritePALMImage() because it needs to
be offset by 256. This can cause a out-of-bounds read later on in the
routine. This could cause impact to reliability.

CVE-2020-25674

WriteOnePNGImage() from coders/png.c (the PNG coder) has a for loop
with an improper exit condition that can allow an out-of-bounds READ
via heap-buffer-overflow. This occurs because it is possible for the
colormap to have less than 256 valid values but the loop condition
will loop 256 times, attempting to pass invalid colormap data to the
event logger.

CVE-2020-27560

ImageMagick allows Division by Zero in OptimizeLayerFrames in
MagickCore/layer.c, which may cause a denial of service.

CVE-2020-27750

A flaw was found in MagickCore/colorspace-private.h and
MagickCore/quantum.h. An attacker who submits a crafted file that is
processedcould trigger undefined behavior in the form of values
outside the range of type `unsigned char` and math division by zero.
This would most likely lead to an impact to application availability,
but could potentially cause other problems related to undefined
behavior.

CVE-2020-27760

In `GammaImage()` of /MagickCore/enhance.c, depending on the `gamma`
value, it's possible to trigger a divide-by-zero condition when a
crafted input file is processed by ImageMagick. This could lead to an
impact to application availability.

CVE-2020-27763

A flaw was found in MagickCore/resize.c. An attacker who submits a
crafted file that is processed by ImageMagick could trigger undefined
behavior in the form of math division by zero. This would most likely
lead to an impact to application availability, but could potentially
cause other problems related to undefined behavior.

CVE-2020-27765

A flaw was found in MagickCore/segment.c. An attacker who submits a
crafted file that is processed by ImageMagick could trigger undefined
behavior in the form of math division by zero. This would most likely
lead to an impact to application availability, but could potentially
cause other problems related to undefined behavior.

CVE-2020-27773

A flaw was found in MagickCore/gem-private.h. An attacker who submits
a crafted file that is processed by ImageMagick could trigger
undefined behavior in the form of values outside the range of type
`unsigned char` or division by zero. This would most likely lead to an
impact to application availability, but could potentially cause other
problems related to undefined behavior.

CVE-2020-29599

ImageMagick mishandles the -authenticate option, which allows setting
a password for password-protected PDF files. The user-controlled
password was not properly escaped/sanitized and it was therefore
possible to inject additional shell commands via coders/pdf.c.

For Debian 9 stretch, these problems have been fixed in version
8:6.9.7.4+dfsg-11+deb9u11.

We recommend that you upgrade your imagemagick packages.

For the detailed security status of imagemagick please refer to its
security tracker page at:
https://security-tracker.debian.org/tracker/imagemagick

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2021/01/msg00010.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/stretch/imagemagick"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/source-package/imagemagick"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:imagemagick");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:imagemagick-6-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:imagemagick-6-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:imagemagick-6.q16");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:imagemagick-6.q16hdri");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:imagemagick-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:imagemagick-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libimage-magick-perl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libimage-magick-q16-perl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libimage-magick-q16hdri-perl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmagick++-6-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmagick++-6.q16-7");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmagick++-6.q16-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmagick++-6.q16hdri-7");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmagick++-6.q16hdri-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmagick++-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmagickcore-6-arch-config");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmagickcore-6-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmagickcore-6.q16-3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmagickcore-6.q16-3-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmagickcore-6.q16-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmagickcore-6.q16hdri-3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmagickcore-6.q16hdri-3-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmagickcore-6.q16hdri-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmagickcore-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmagickwand-6-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmagickwand-6.q16-3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmagickwand-6.q16-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmagickwand-6.q16hdri-3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmagickwand-6.q16hdri-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmagickwand-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:perlmagick");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:9.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/09/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/01/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/01/13");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (deb_check(release:"9.0", prefix:"imagemagick", reference:"8:6.9.7.4+dfsg-11+deb9u11")) flag++;
if (deb_check(release:"9.0", prefix:"imagemagick-6-common", reference:"8:6.9.7.4+dfsg-11+deb9u11")) flag++;
if (deb_check(release:"9.0", prefix:"imagemagick-6-doc", reference:"8:6.9.7.4+dfsg-11+deb9u11")) flag++;
if (deb_check(release:"9.0", prefix:"imagemagick-6.q16", reference:"8:6.9.7.4+dfsg-11+deb9u11")) flag++;
if (deb_check(release:"9.0", prefix:"imagemagick-6.q16hdri", reference:"8:6.9.7.4+dfsg-11+deb9u11")) flag++;
if (deb_check(release:"9.0", prefix:"imagemagick-common", reference:"8:6.9.7.4+dfsg-11+deb9u11")) flag++;
if (deb_check(release:"9.0", prefix:"imagemagick-doc", reference:"8:6.9.7.4+dfsg-11+deb9u11")) flag++;
if (deb_check(release:"9.0", prefix:"libimage-magick-perl", reference:"8:6.9.7.4+dfsg-11+deb9u11")) flag++;
if (deb_check(release:"9.0", prefix:"libimage-magick-q16-perl", reference:"8:6.9.7.4+dfsg-11+deb9u11")) flag++;
if (deb_check(release:"9.0", prefix:"libimage-magick-q16hdri-perl", reference:"8:6.9.7.4+dfsg-11+deb9u11")) flag++;
if (deb_check(release:"9.0", prefix:"libmagick++-6-headers", reference:"8:6.9.7.4+dfsg-11+deb9u11")) flag++;
if (deb_check(release:"9.0", prefix:"libmagick++-6.q16-7", reference:"8:6.9.7.4+dfsg-11+deb9u11")) flag++;
if (deb_check(release:"9.0", prefix:"libmagick++-6.q16-dev", reference:"8:6.9.7.4+dfsg-11+deb9u11")) flag++;
if (deb_check(release:"9.0", prefix:"libmagick++-6.q16hdri-7", reference:"8:6.9.7.4+dfsg-11+deb9u11")) flag++;
if (deb_check(release:"9.0", prefix:"libmagick++-6.q16hdri-dev", reference:"8:6.9.7.4+dfsg-11+deb9u11")) flag++;
if (deb_check(release:"9.0", prefix:"libmagick++-dev", reference:"8:6.9.7.4+dfsg-11+deb9u11")) flag++;
if (deb_check(release:"9.0", prefix:"libmagickcore-6-arch-config", reference:"8:6.9.7.4+dfsg-11+deb9u11")) flag++;
if (deb_check(release:"9.0", prefix:"libmagickcore-6-headers", reference:"8:6.9.7.4+dfsg-11+deb9u11")) flag++;
if (deb_check(release:"9.0", prefix:"libmagickcore-6.q16-3", reference:"8:6.9.7.4+dfsg-11+deb9u11")) flag++;
if (deb_check(release:"9.0", prefix:"libmagickcore-6.q16-3-extra", reference:"8:6.9.7.4+dfsg-11+deb9u11")) flag++;
if (deb_check(release:"9.0", prefix:"libmagickcore-6.q16-dev", reference:"8:6.9.7.4+dfsg-11+deb9u11")) flag++;
if (deb_check(release:"9.0", prefix:"libmagickcore-6.q16hdri-3", reference:"8:6.9.7.4+dfsg-11+deb9u11")) flag++;
if (deb_check(release:"9.0", prefix:"libmagickcore-6.q16hdri-3-extra", reference:"8:6.9.7.4+dfsg-11+deb9u11")) flag++;
if (deb_check(release:"9.0", prefix:"libmagickcore-6.q16hdri-dev", reference:"8:6.9.7.4+dfsg-11+deb9u11")) flag++;
if (deb_check(release:"9.0", prefix:"libmagickcore-dev", reference:"8:6.9.7.4+dfsg-11+deb9u11")) flag++;
if (deb_check(release:"9.0", prefix:"libmagickwand-6-headers", reference:"8:6.9.7.4+dfsg-11+deb9u11")) flag++;
if (deb_check(release:"9.0", prefix:"libmagickwand-6.q16-3", reference:"8:6.9.7.4+dfsg-11+deb9u11")) flag++;
if (deb_check(release:"9.0", prefix:"libmagickwand-6.q16-dev", reference:"8:6.9.7.4+dfsg-11+deb9u11")) flag++;
if (deb_check(release:"9.0", prefix:"libmagickwand-6.q16hdri-3", reference:"8:6.9.7.4+dfsg-11+deb9u11")) flag++;
if (deb_check(release:"9.0", prefix:"libmagickwand-6.q16hdri-dev", reference:"8:6.9.7.4+dfsg-11+deb9u11")) flag++;
if (deb_check(release:"9.0", prefix:"libmagickwand-dev", reference:"8:6.9.7.4+dfsg-11+deb9u11")) flag++;
if (deb_check(release:"9.0", prefix:"perlmagick", reference:"8:6.9.7.4+dfsg-11+deb9u11")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
