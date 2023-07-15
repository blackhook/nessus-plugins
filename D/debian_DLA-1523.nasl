#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-1523-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(117810);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/11");

  script_cve_id("CVE-2018-17281");

  script_name(english:"Debian DLA-1523-1 : asterisk security update");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Sean Bright discovered that Asterisk, a PBX and telephony toolkit,
contained a stack overflow vulnerability in the res_http_websocket.so
module that allowed remote attackers to crash Asterisk via specially
crafted HTTP requests to upgrade the connection to a websocket.

For Debian 8 'Jessie', this problem has been fixed in version
1:11.13.1~dfsg-2+deb8u6.

We recommend that you upgrade your asterisk packages.

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2018/09/msg00034.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/jessie/asterisk"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:asterisk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:asterisk-config");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:asterisk-dahdi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:asterisk-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:asterisk-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:asterisk-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:asterisk-mobile");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:asterisk-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:asterisk-mp3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:asterisk-mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:asterisk-ooh323");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:asterisk-voicemail");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:asterisk-voicemail-imapstorage");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:asterisk-voicemail-odbcstorage");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:asterisk-vpb");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:8.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2018/09/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/09/28");
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
if (deb_check(release:"8.0", prefix:"asterisk", reference:"1:11.13.1~dfsg-2+deb8u6")) flag++;
if (deb_check(release:"8.0", prefix:"asterisk-config", reference:"1:11.13.1~dfsg-2+deb8u6")) flag++;
if (deb_check(release:"8.0", prefix:"asterisk-dahdi", reference:"1:11.13.1~dfsg-2+deb8u6")) flag++;
if (deb_check(release:"8.0", prefix:"asterisk-dbg", reference:"1:11.13.1~dfsg-2+deb8u6")) flag++;
if (deb_check(release:"8.0", prefix:"asterisk-dev", reference:"1:11.13.1~dfsg-2+deb8u6")) flag++;
if (deb_check(release:"8.0", prefix:"asterisk-doc", reference:"1:11.13.1~dfsg-2+deb8u6")) flag++;
if (deb_check(release:"8.0", prefix:"asterisk-mobile", reference:"1:11.13.1~dfsg-2+deb8u6")) flag++;
if (deb_check(release:"8.0", prefix:"asterisk-modules", reference:"1:11.13.1~dfsg-2+deb8u6")) flag++;
if (deb_check(release:"8.0", prefix:"asterisk-mp3", reference:"1:11.13.1~dfsg-2+deb8u6")) flag++;
if (deb_check(release:"8.0", prefix:"asterisk-mysql", reference:"1:11.13.1~dfsg-2+deb8u6")) flag++;
if (deb_check(release:"8.0", prefix:"asterisk-ooh323", reference:"1:11.13.1~dfsg-2+deb8u6")) flag++;
if (deb_check(release:"8.0", prefix:"asterisk-voicemail", reference:"1:11.13.1~dfsg-2+deb8u6")) flag++;
if (deb_check(release:"8.0", prefix:"asterisk-voicemail-imapstorage", reference:"1:11.13.1~dfsg-2+deb8u6")) flag++;
if (deb_check(release:"8.0", prefix:"asterisk-voicemail-odbcstorage", reference:"1:11.13.1~dfsg-2+deb8u6")) flag++;
if (deb_check(release:"8.0", prefix:"asterisk-vpb", reference:"1:11.13.1~dfsg-2+deb8u6")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
