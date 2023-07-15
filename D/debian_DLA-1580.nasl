#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-1580-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(119039);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/11");

  script_cve_id("CVE-2018-1049", "CVE-2018-15686", "CVE-2018-15688");

  script_name(english:"Debian DLA-1580-1 : systemd security update");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"systemd was found to suffer from multiple security vulnerabilities
ranging from denial of service attacks to possible root privilege
escalation.

CVE-2018-1049

A race condition exists between .mount and .automount units such that
automount requests from kernel may not be serviced by systemd
resulting in kernel holding the mountpoint and any processes that try
to use said mount will hang. A race condition like this may lead to
denial of service, until mount points are unmounted.

CVE-2018-15686

A vulnerability in unit_deserialize of systemd allows an attacker to
supply arbitrary state across systemd re-execution via NotifyAccess.
This can be used to improperly influence systemd execution and
possibly lead to root privilege escalation.

CVE-2018-15688

A buffer overflow vulnerability in the dhcp6 client of systemd allows
a malicious dhcp6 server to overwrite heap memory in systemd-networkd,
which is not enabled by default in Debian.

For Debian 8 'Jessie', these problems have been fixed in version
215-17+deb8u8.

We recommend that you upgrade your systemd packages.

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2018/11/msg00017.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/jessie/systemd"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:gir1.2-gudev-1.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libgudev-1.0-0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libgudev-1.0-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libpam-systemd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libsystemd-daemon-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libsystemd-daemon0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libsystemd-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libsystemd-id128-0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libsystemd-id128-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libsystemd-journal-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libsystemd-journal0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libsystemd-login-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libsystemd-login0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libsystemd0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libudev-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libudev1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libudev1-udeb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:python3-systemd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:systemd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:systemd-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:systemd-sysv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:udev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:udev-udeb");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:8.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2018/11/19");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/11/20");
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
if (deb_check(release:"8.0", prefix:"gir1.2-gudev-1.0", reference:"215-17+deb8u8")) flag++;
if (deb_check(release:"8.0", prefix:"libgudev-1.0-0", reference:"215-17+deb8u8")) flag++;
if (deb_check(release:"8.0", prefix:"libgudev-1.0-dev", reference:"215-17+deb8u8")) flag++;
if (deb_check(release:"8.0", prefix:"libpam-systemd", reference:"215-17+deb8u8")) flag++;
if (deb_check(release:"8.0", prefix:"libsystemd-daemon-dev", reference:"215-17+deb8u8")) flag++;
if (deb_check(release:"8.0", prefix:"libsystemd-daemon0", reference:"215-17+deb8u8")) flag++;
if (deb_check(release:"8.0", prefix:"libsystemd-dev", reference:"215-17+deb8u8")) flag++;
if (deb_check(release:"8.0", prefix:"libsystemd-id128-0", reference:"215-17+deb8u8")) flag++;
if (deb_check(release:"8.0", prefix:"libsystemd-id128-dev", reference:"215-17+deb8u8")) flag++;
if (deb_check(release:"8.0", prefix:"libsystemd-journal-dev", reference:"215-17+deb8u8")) flag++;
if (deb_check(release:"8.0", prefix:"libsystemd-journal0", reference:"215-17+deb8u8")) flag++;
if (deb_check(release:"8.0", prefix:"libsystemd-login-dev", reference:"215-17+deb8u8")) flag++;
if (deb_check(release:"8.0", prefix:"libsystemd-login0", reference:"215-17+deb8u8")) flag++;
if (deb_check(release:"8.0", prefix:"libsystemd0", reference:"215-17+deb8u8")) flag++;
if (deb_check(release:"8.0", prefix:"libudev-dev", reference:"215-17+deb8u8")) flag++;
if (deb_check(release:"8.0", prefix:"libudev1", reference:"215-17+deb8u8")) flag++;
if (deb_check(release:"8.0", prefix:"libudev1-udeb", reference:"215-17+deb8u8")) flag++;
if (deb_check(release:"8.0", prefix:"python3-systemd", reference:"215-17+deb8u8")) flag++;
if (deb_check(release:"8.0", prefix:"systemd", reference:"215-17+deb8u8")) flag++;
if (deb_check(release:"8.0", prefix:"systemd-dbg", reference:"215-17+deb8u8")) flag++;
if (deb_check(release:"8.0", prefix:"systemd-sysv", reference:"215-17+deb8u8")) flag++;
if (deb_check(release:"8.0", prefix:"udev", reference:"215-17+deb8u8")) flag++;
if (deb_check(release:"8.0", prefix:"udev-udeb", reference:"215-17+deb8u8")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
