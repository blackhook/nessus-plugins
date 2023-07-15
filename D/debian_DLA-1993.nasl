#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-1993-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(131084);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/11");

  script_cve_id("CVE-2019-5068");

  script_name(english:"Debian DLA-1993-1 : mesa security update");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Tim Brown discovered a shared memory permissions vulnerability in the
Mesa 3D graphics library. Some Mesa X11 drivers use shared-memory
XImages to implement back buffers for improved performance, but Mesa
creates shared memory regions with permission mode 0777. An attacker
can access the shared memory without any specific permissions.

For Debian 8 'Jessie', this problem has been fixed in version
10.3.2-1+deb8u2.

We recommend that you upgrade your mesa packages.

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2019/11/msg00013.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/jessie/mesa"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libegl1-mesa");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libegl1-mesa-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libegl1-mesa-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libegl1-mesa-drivers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libegl1-mesa-drivers-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libgbm-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libgbm1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libgbm1-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libgl1-mesa-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libgl1-mesa-dri");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libgl1-mesa-dri-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libgl1-mesa-glx");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libgl1-mesa-glx-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libgl1-mesa-swx11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libgl1-mesa-swx11-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libgl1-mesa-swx11-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libgl1-mesa-swx11-i686");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libglapi-mesa");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libglapi-mesa-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libgles1-mesa");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libgles1-mesa-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libgles1-mesa-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libgles2-mesa");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libgles2-mesa-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libgles2-mesa-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libopenvg1-mesa");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libopenvg1-mesa-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libopenvg1-mesa-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libosmesa6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libosmesa6-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libwayland-egl1-mesa");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libwayland-egl1-mesa-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libxatracker-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libxatracker2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libxatracker2-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mesa-common-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mesa-opencl-icd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mesa-opencl-icd-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mesa-vdpau-drivers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mesa-vdpau-drivers-dbg");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:8.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/11/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/11/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/11/18");
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
if (deb_check(release:"8.0", prefix:"libegl1-mesa", reference:"10.3.2-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"libegl1-mesa-dbg", reference:"10.3.2-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"libegl1-mesa-dev", reference:"10.3.2-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"libegl1-mesa-drivers", reference:"10.3.2-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"libegl1-mesa-drivers-dbg", reference:"10.3.2-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"libgbm-dev", reference:"10.3.2-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"libgbm1", reference:"10.3.2-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"libgbm1-dbg", reference:"10.3.2-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"libgl1-mesa-dev", reference:"10.3.2-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"libgl1-mesa-dri", reference:"10.3.2-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"libgl1-mesa-dri-dbg", reference:"10.3.2-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"libgl1-mesa-glx", reference:"10.3.2-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"libgl1-mesa-glx-dbg", reference:"10.3.2-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"libgl1-mesa-swx11", reference:"10.3.2-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"libgl1-mesa-swx11-dbg", reference:"10.3.2-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"libgl1-mesa-swx11-dev", reference:"10.3.2-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"libgl1-mesa-swx11-i686", reference:"10.3.2-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"libglapi-mesa", reference:"10.3.2-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"libglapi-mesa-dbg", reference:"10.3.2-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"libgles1-mesa", reference:"10.3.2-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"libgles1-mesa-dbg", reference:"10.3.2-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"libgles1-mesa-dev", reference:"10.3.2-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"libgles2-mesa", reference:"10.3.2-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"libgles2-mesa-dbg", reference:"10.3.2-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"libgles2-mesa-dev", reference:"10.3.2-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"libopenvg1-mesa", reference:"10.3.2-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"libopenvg1-mesa-dbg", reference:"10.3.2-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"libopenvg1-mesa-dev", reference:"10.3.2-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"libosmesa6", reference:"10.3.2-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"libosmesa6-dev", reference:"10.3.2-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"libwayland-egl1-mesa", reference:"10.3.2-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"libwayland-egl1-mesa-dbg", reference:"10.3.2-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"libxatracker-dev", reference:"10.3.2-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"libxatracker2", reference:"10.3.2-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"libxatracker2-dbg", reference:"10.3.2-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"mesa-common-dev", reference:"10.3.2-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"mesa-opencl-icd", reference:"10.3.2-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"mesa-opencl-icd-dbg", reference:"10.3.2-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"mesa-vdpau-drivers", reference:"10.3.2-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"mesa-vdpau-drivers-dbg", reference:"10.3.2-1+deb8u2")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_note(port:0, extra:deb_report_get());
  else security_note(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
