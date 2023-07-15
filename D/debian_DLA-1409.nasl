#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-1409-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(110818);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/11");

  script_cve_id("CVE-2017-7651", "CVE-2017-7652");

  script_name(english:"Debian DLA-1409-1 : mosquitto security update");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"CVE-2017-7651 fix to avoid extraordinary memory consumption by crafted
CONNECT packet from unauthenticated client

CVE-2017-7652 in case all sockets/file descriptors are exhausted, this
is a fix to avoid default config values after reloading configuration
by SIGHUP signal

For Debian 8 'Jessie', these problems have been fixed in version
1.3.4-2+deb8u2.

We recommend that you upgrade your mosquitto packages.

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2018/06/msg00016.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/jessie/mosquitto"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmosquitto-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmosquitto1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmosquittopp-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmosquittopp1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mosquitto");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mosquitto-clients");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mosquitto-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:python-mosquitto");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:python3-mosquitto");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:8.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2018/06/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/07/02");
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
if (deb_check(release:"8.0", prefix:"libmosquitto-dev", reference:"1.3.4-2+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"libmosquitto1", reference:"1.3.4-2+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"libmosquittopp-dev", reference:"1.3.4-2+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"libmosquittopp1", reference:"1.3.4-2+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"mosquitto", reference:"1.3.4-2+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"mosquitto-clients", reference:"1.3.4-2+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"mosquitto-dbg", reference:"1.3.4-2+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"python-mosquitto", reference:"1.3.4-2+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"python3-mosquitto", reference:"1.3.4-2+deb8u2")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
