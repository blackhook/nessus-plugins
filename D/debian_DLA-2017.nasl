#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-2017-2. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(131435);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/11");

  script_name(english:"Debian DLA-2017-2 : asterisk regression update");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The backport of the CVE-2019-13161 fix caused a regression and has
been reverted.

For Debian 8 'Jessie', this problem has been fixed in version
1:11.13.1~dfsg-2+deb8u8.

We recommend that you upgrade your asterisk packages.

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2019/12/msg00000.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/jessie/asterisk"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade the affected packages.");
  script_set_attribute(attribute:"risk_factor", value:"High");

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

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/12/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/12/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/12/03");
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
if (deb_check(release:"8.0", prefix:"asterisk", reference:"1:11.13.1~dfsg-2+deb8u8")) flag++;
if (deb_check(release:"8.0", prefix:"asterisk-config", reference:"1:11.13.1~dfsg-2+deb8u8")) flag++;
if (deb_check(release:"8.0", prefix:"asterisk-dahdi", reference:"1:11.13.1~dfsg-2+deb8u8")) flag++;
if (deb_check(release:"8.0", prefix:"asterisk-dbg", reference:"1:11.13.1~dfsg-2+deb8u8")) flag++;
if (deb_check(release:"8.0", prefix:"asterisk-dev", reference:"1:11.13.1~dfsg-2+deb8u8")) flag++;
if (deb_check(release:"8.0", prefix:"asterisk-doc", reference:"1:11.13.1~dfsg-2+deb8u8")) flag++;
if (deb_check(release:"8.0", prefix:"asterisk-mobile", reference:"1:11.13.1~dfsg-2+deb8u8")) flag++;
if (deb_check(release:"8.0", prefix:"asterisk-modules", reference:"1:11.13.1~dfsg-2+deb8u8")) flag++;
if (deb_check(release:"8.0", prefix:"asterisk-mp3", reference:"1:11.13.1~dfsg-2+deb8u8")) flag++;
if (deb_check(release:"8.0", prefix:"asterisk-mysql", reference:"1:11.13.1~dfsg-2+deb8u8")) flag++;
if (deb_check(release:"8.0", prefix:"asterisk-ooh323", reference:"1:11.13.1~dfsg-2+deb8u8")) flag++;
if (deb_check(release:"8.0", prefix:"asterisk-voicemail", reference:"1:11.13.1~dfsg-2+deb8u8")) flag++;
if (deb_check(release:"8.0", prefix:"asterisk-voicemail-imapstorage", reference:"1:11.13.1~dfsg-2+deb8u8")) flag++;
if (deb_check(release:"8.0", prefix:"asterisk-voicemail-odbcstorage", reference:"1:11.13.1~dfsg-2+deb8u8")) flag++;
if (deb_check(release:"8.0", prefix:"asterisk-vpb", reference:"1:11.13.1~dfsg-2+deb8u8")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
