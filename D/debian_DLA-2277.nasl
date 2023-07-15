#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-2277-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(138391);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/07/16");

  script_cve_id("CVE-2019-12973", "CVE-2020-15389", "CVE-2020-6851", "CVE-2020-8112");

  script_name(english:"Debian DLA-2277-1 : openjpeg2 security update");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The following CVEs were reported against src:openjpeg2.

CVE-2019-12973

In OpenJPEG 2.3.1, there is excessive iteration in the
opj_t1_encode_cblks function of openjp2/t1.c. Remote attackers could
leverage this vulnerability to cause a denial of service via a crafted
bmp file. This issue is similar to CVE-2018-6616.

CVE-2020-6851

OpenJPEG through 2.3.1 has a heap-based buffer overflow in
opj_t1_clbl_decode_processor in openjp2/t1.c because of lack of
opj_j2k_update_image_dimensions validation.

CVE-2020-8112

opj_t1_clbl_decode_processor in openjp2/t1.c in OpenJPEG 2.3.1 through
2020-01-28 has a heap-based buffer overflow in the qmfbid==1 case, a
different issue than CVE-2020-6851.

CVE-2020-15389

jp2/opj_decompress.c in OpenJPEG through 2.3.1 has a use-after-free
that can be triggered if there is a mix of valid and invalid files in
a directory operated on by the decompressor. Triggering a double-free
may also be possible. This is related to calling opj_image_destroy
twice.

For Debian 9 stretch, these problems have been fixed in version
2.1.2-1.1+deb9u5.

We recommend that you upgrade your openjpeg2 packages.

For the detailed security status of openjpeg2 please refer to its
security tracker page at:
https://security-tracker.debian.org/tracker/openjpeg2

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2020/07/msg00008.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/stretch/openjpeg2"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/source-package/openjpeg2"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libopenjp2-7");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libopenjp2-7-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libopenjp2-7-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libopenjp2-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libopenjp3d-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libopenjp3d7");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libopenjpip-dec-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libopenjpip-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libopenjpip-viewer");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libopenjpip7");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:9.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/06/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/07/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/07/14");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (deb_check(release:"9.0", prefix:"libopenjp2-7", reference:"2.1.2-1.1+deb9u5")) flag++;
if (deb_check(release:"9.0", prefix:"libopenjp2-7-dbg", reference:"2.1.2-1.1+deb9u5")) flag++;
if (deb_check(release:"9.0", prefix:"libopenjp2-7-dev", reference:"2.1.2-1.1+deb9u5")) flag++;
if (deb_check(release:"9.0", prefix:"libopenjp2-tools", reference:"2.1.2-1.1+deb9u5")) flag++;
if (deb_check(release:"9.0", prefix:"libopenjp3d-tools", reference:"2.1.2-1.1+deb9u5")) flag++;
if (deb_check(release:"9.0", prefix:"libopenjp3d7", reference:"2.1.2-1.1+deb9u5")) flag++;
if (deb_check(release:"9.0", prefix:"libopenjpip-dec-server", reference:"2.1.2-1.1+deb9u5")) flag++;
if (deb_check(release:"9.0", prefix:"libopenjpip-server", reference:"2.1.2-1.1+deb9u5")) flag++;
if (deb_check(release:"9.0", prefix:"libopenjpip-viewer", reference:"2.1.2-1.1+deb9u5")) flag++;
if (deb_check(release:"9.0", prefix:"libopenjpip7", reference:"2.1.2-1.1+deb9u5")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
