#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-1851-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(126607);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/11");

  script_cve_id("CVE-2016-9112", "CVE-2018-20847");

  script_name(english:"Debian DLA-1851-1 : openjpeg2 security update");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Two security vulnerabilities were discovered in openjpeg2, a JPEG 2000
image library.

CVE-2016-9112

A floating point exception or divide by zero in the function
opj_pi_next_cprl may lead to a denial of service.

CVE-2018-20847

An improper computation of values in the function
opj_get_encoding_parameters can lead to an integer overflow. This
issue was partly fixed by the patch for CVE-2015-1239.

For Debian 8 'Jessie', these problems have been fixed in version
2.1.0-2+deb8u7.

We recommend that you upgrade your openjpeg2 packages.

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2019/07/msg00010.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/jessie/openjpeg2"
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
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:8.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/10/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/07/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/07/11");
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
if (deb_check(release:"8.0", prefix:"libopenjp2-7", reference:"2.1.0-2+deb8u7")) flag++;
if (deb_check(release:"8.0", prefix:"libopenjp2-7-dbg", reference:"2.1.0-2+deb8u7")) flag++;
if (deb_check(release:"8.0", prefix:"libopenjp2-7-dev", reference:"2.1.0-2+deb8u7")) flag++;
if (deb_check(release:"8.0", prefix:"libopenjp2-tools", reference:"2.1.0-2+deb8u7")) flag++;
if (deb_check(release:"8.0", prefix:"libopenjp3d-tools", reference:"2.1.0-2+deb8u7")) flag++;
if (deb_check(release:"8.0", prefix:"libopenjp3d7", reference:"2.1.0-2+deb8u7")) flag++;
if (deb_check(release:"8.0", prefix:"libopenjpip-dec-server", reference:"2.1.0-2+deb8u7")) flag++;
if (deb_check(release:"8.0", prefix:"libopenjpip-server", reference:"2.1.0-2+deb8u7")) flag++;
if (deb_check(release:"8.0", prefix:"libopenjpip-viewer", reference:"2.1.0-2+deb8u7")) flag++;
if (deb_check(release:"8.0", prefix:"libopenjpip7", reference:"2.1.0-2+deb8u7")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
