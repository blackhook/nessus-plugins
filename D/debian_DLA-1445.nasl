#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-1445-3. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(111358);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/11");

  script_name(english:"Debian DLA-1445-3 : busybox regression update");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"It was found that the security update of busybox announced as
DLA-1445-1 to prevent the exploitation of CVE-2011-5325, a symlinking
attack, was too strict in case of cpio archives. This update restores
the old behavior.

For Debian 8 'Jessie', this problem has been fixed in version
1:1.22.0-9+deb8u4.

We recommend that you upgrade your busybox packages.

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2018/08/msg00003.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/jessie/busybox"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade the affected packages.");
  script_set_attribute(attribute:"risk_factor", value:"High");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:busybox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:busybox-static");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:busybox-syslogd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:busybox-udeb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:udhcpc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:udhcpd");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:8.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2018/08/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/07/27");
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
if (deb_check(release:"8.0", prefix:"busybox", reference:"1:1.22.0-9+deb8u4")) flag++;
if (deb_check(release:"8.0", prefix:"busybox-static", reference:"1:1.22.0-9+deb8u4")) flag++;
if (deb_check(release:"8.0", prefix:"busybox-syslogd", reference:"1:1.22.0-9+deb8u4")) flag++;
if (deb_check(release:"8.0", prefix:"busybox-udeb", reference:"1:1.22.0-9+deb8u4")) flag++;
if (deb_check(release:"8.0", prefix:"udhcpc", reference:"1:1.22.0-9+deb8u4")) flag++;
if (deb_check(release:"8.0", prefix:"udhcpd", reference:"1:1.22.0-9+deb8u4")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
