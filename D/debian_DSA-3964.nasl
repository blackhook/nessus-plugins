#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-3964. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(102931);
  script_version("3.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2017-14099", "CVE-2017-14100");
  script_xref(name:"DSA", value:"3964");

  script_name(english:"Debian DSA-3964-1 : asterisk - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Multiple vulnerabilities have been discovered in Asterisk, an open
source PBX and telephony toolkit, which may result in disclosure of
RTP connections or the execution of arbitrary shell commands.

For additional information please refer to the upstream advisories:
http://downloads.asterisk.org/pub/security/AST-2017-005.html,
http://downloads.asterisk.org/pub/security/AST-2017-006.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://downloads.asterisk.org/pub/security/AST-2017-005.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://downloads.asterisk.org/pub/security/AST-2017-006.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/jessie/asterisk"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/stretch/asterisk"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.debian.org/security/2017/dsa-3964"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the asterisk packages.

For the oldstable distribution (jessie), these problems have been
fixed in version 1:11.13.1~dfsg-2+deb8u3.

For the stable distribution (stretch), these problems have been fixed
in version 1:13.14.1~dfsg-2+deb9u1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:asterisk");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:8.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:9.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/09/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/09/05");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (deb_check(release:"8.0", prefix:"asterisk", reference:"1:11.13.1~dfsg-2+deb8u3")) flag++;
if (deb_check(release:"8.0", prefix:"asterisk-config", reference:"1:11.13.1~dfsg-2+deb8u3")) flag++;
if (deb_check(release:"8.0", prefix:"asterisk-dahdi", reference:"1:11.13.1~dfsg-2+deb8u3")) flag++;
if (deb_check(release:"8.0", prefix:"asterisk-dbg", reference:"1:11.13.1~dfsg-2+deb8u3")) flag++;
if (deb_check(release:"8.0", prefix:"asterisk-dev", reference:"1:11.13.1~dfsg-2+deb8u3")) flag++;
if (deb_check(release:"8.0", prefix:"asterisk-doc", reference:"1:11.13.1~dfsg-2+deb8u3")) flag++;
if (deb_check(release:"8.0", prefix:"asterisk-mobile", reference:"1:11.13.1~dfsg-2+deb8u3")) flag++;
if (deb_check(release:"8.0", prefix:"asterisk-modules", reference:"1:11.13.1~dfsg-2+deb8u3")) flag++;
if (deb_check(release:"8.0", prefix:"asterisk-mp3", reference:"1:11.13.1~dfsg-2+deb8u3")) flag++;
if (deb_check(release:"8.0", prefix:"asterisk-mysql", reference:"1:11.13.1~dfsg-2+deb8u3")) flag++;
if (deb_check(release:"8.0", prefix:"asterisk-ooh323", reference:"1:11.13.1~dfsg-2+deb8u3")) flag++;
if (deb_check(release:"8.0", prefix:"asterisk-voicemail", reference:"1:11.13.1~dfsg-2+deb8u3")) flag++;
if (deb_check(release:"8.0", prefix:"asterisk-voicemail-imapstorage", reference:"1:11.13.1~dfsg-2+deb8u3")) flag++;
if (deb_check(release:"8.0", prefix:"asterisk-voicemail-odbcstorage", reference:"1:11.13.1~dfsg-2+deb8u3")) flag++;
if (deb_check(release:"8.0", prefix:"asterisk-vpb", reference:"1:11.13.1~dfsg-2+deb8u3")) flag++;
if (deb_check(release:"9.0", prefix:"asterisk", reference:"1:13.14.1~dfsg-2+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"asterisk-config", reference:"1:13.14.1~dfsg-2+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"asterisk-dahdi", reference:"1:13.14.1~dfsg-2+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"asterisk-dev", reference:"1:13.14.1~dfsg-2+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"asterisk-doc", reference:"1:13.14.1~dfsg-2+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"asterisk-mobile", reference:"1:13.14.1~dfsg-2+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"asterisk-modules", reference:"1:13.14.1~dfsg-2+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"asterisk-mp3", reference:"1:13.14.1~dfsg-2+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"asterisk-mysql", reference:"1:13.14.1~dfsg-2+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"asterisk-ooh323", reference:"1:13.14.1~dfsg-2+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"asterisk-voicemail", reference:"1:13.14.1~dfsg-2+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"asterisk-voicemail-imapstorage", reference:"1:13.14.1~dfsg-2+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"asterisk-voicemail-odbcstorage", reference:"1:13.14.1~dfsg-2+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"asterisk-vpb", reference:"1:13.14.1~dfsg-2+deb9u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
