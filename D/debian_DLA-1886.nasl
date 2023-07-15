#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-1886-2. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(127922);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/11");

  script_name(english:"Debian DLA-1886-2 : openjdk-7 regression update");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The latest security update of openjdk-7 caused a regression when
applications relied on elliptic curve algorithms to establish SSL
connections. Several duplicate classes were removed from rt.jar by the
upstream developers of OpenJDK because they were also present in
sunec.jar. However Debian never shipped the SunEC security provider in
OpenJDK 7.

The issue was resolved by building sunec.jar and its corresponding
native library libsunec.so from source. In order to build these
libraries from source, an update of nss to version 2:3.26-1+debu8u6 is
required.

Updates for the amd64 architecture are already available, new packages
for i386, armel and armhf will be available within the next 24 hours.

For Debian 8 'Jessie', this problem has been fixed in version
7u231-2.6.19-1~deb8u2.

We recommend that you upgrade your openjdk-7 packages.

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2019/08/msg00027.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/jessie/openjdk-7"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade the affected packages.");
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:icedtea-7-jre-jamvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:openjdk-7-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:openjdk-7-demo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:openjdk-7-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:openjdk-7-jdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:openjdk-7-jre");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:openjdk-7-jre-headless");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:openjdk-7-jre-lib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:openjdk-7-jre-zero");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:openjdk-7-source");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:8.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/08/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/08/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/08/20");
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
if (deb_check(release:"8.0", prefix:"icedtea-7-jre-jamvm", reference:"7u231-2.6.19-1~deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"openjdk-7-dbg", reference:"7u231-2.6.19-1~deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"openjdk-7-demo", reference:"7u231-2.6.19-1~deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"openjdk-7-doc", reference:"7u231-2.6.19-1~deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"openjdk-7-jdk", reference:"7u231-2.6.19-1~deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"openjdk-7-jre", reference:"7u231-2.6.19-1~deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"openjdk-7-jre-headless", reference:"7u231-2.6.19-1~deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"openjdk-7-jre-lib", reference:"7u231-2.6.19-1~deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"openjdk-7-jre-zero", reference:"7u231-2.6.19-1~deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"openjdk-7-source", reference:"7u231-2.6.19-1~deb8u2")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
