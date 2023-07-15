#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-1443-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(111315);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/11");

  script_name(english:"Debian DLA-1443-1 : evolution-data-server security update");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"It was discovered that there was a protocol implementation error in
evolution-data-server where 'STARTTLS not supported' errors from IMAP
servers were ignored leading to the use of insecure connections
without the user's knowledge or consent.

For Debian 8 'Jessie', this issue has been fixed in
evolution-data-server version 3.12.9~git20141128.5242b0-2+deb8u4.

We recommend that you upgrade your evolution-data-server packages.

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2018/07/msg00035.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/jessie/evolution-data-server"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade the affected packages.");
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:evolution-data-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:evolution-data-server-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:evolution-data-server-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:evolution-data-server-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:evolution-data-server-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:gir1.2-ebook-1.2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:gir1.2-ebookcontacts-1.2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:gir1.2-edataserver-1.2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libcamel-1.2-49");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libcamel1.2-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libebackend-1.2-7");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libebackend1.2-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libebook-1.2-14");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libebook-contacts-1.2-0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libebook-contacts1.2-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libebook1.2-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libecal-1.2-16");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libecal1.2-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libedata-book-1.2-20");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libedata-book1.2-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libedata-cal-1.2-23");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libedata-cal1.2-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libedataserver-1.2-18");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libedataserver1.2-dev");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:8.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2018/07/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/07/25");
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
if (deb_check(release:"8.0", prefix:"evolution-data-server", reference:"3.12.9~git20141128.5242b0-2+deb8u4")) flag++;
if (deb_check(release:"8.0", prefix:"evolution-data-server-common", reference:"3.12.9~git20141128.5242b0-2+deb8u4")) flag++;
if (deb_check(release:"8.0", prefix:"evolution-data-server-dbg", reference:"3.12.9~git20141128.5242b0-2+deb8u4")) flag++;
if (deb_check(release:"8.0", prefix:"evolution-data-server-dev", reference:"3.12.9~git20141128.5242b0-2+deb8u4")) flag++;
if (deb_check(release:"8.0", prefix:"evolution-data-server-doc", reference:"3.12.9~git20141128.5242b0-2+deb8u4")) flag++;
if (deb_check(release:"8.0", prefix:"gir1.2-ebook-1.2", reference:"3.12.9~git20141128.5242b0-2+deb8u4")) flag++;
if (deb_check(release:"8.0", prefix:"gir1.2-ebookcontacts-1.2", reference:"3.12.9~git20141128.5242b0-2+deb8u4")) flag++;
if (deb_check(release:"8.0", prefix:"gir1.2-edataserver-1.2", reference:"3.12.9~git20141128.5242b0-2+deb8u4")) flag++;
if (deb_check(release:"8.0", prefix:"libcamel-1.2-49", reference:"3.12.9~git20141128.5242b0-2+deb8u4")) flag++;
if (deb_check(release:"8.0", prefix:"libcamel1.2-dev", reference:"3.12.9~git20141128.5242b0-2+deb8u4")) flag++;
if (deb_check(release:"8.0", prefix:"libebackend-1.2-7", reference:"3.12.9~git20141128.5242b0-2+deb8u4")) flag++;
if (deb_check(release:"8.0", prefix:"libebackend1.2-dev", reference:"3.12.9~git20141128.5242b0-2+deb8u4")) flag++;
if (deb_check(release:"8.0", prefix:"libebook-1.2-14", reference:"3.12.9~git20141128.5242b0-2+deb8u4")) flag++;
if (deb_check(release:"8.0", prefix:"libebook-contacts-1.2-0", reference:"3.12.9~git20141128.5242b0-2+deb8u4")) flag++;
if (deb_check(release:"8.0", prefix:"libebook-contacts1.2-dev", reference:"3.12.9~git20141128.5242b0-2+deb8u4")) flag++;
if (deb_check(release:"8.0", prefix:"libebook1.2-dev", reference:"3.12.9~git20141128.5242b0-2+deb8u4")) flag++;
if (deb_check(release:"8.0", prefix:"libecal-1.2-16", reference:"3.12.9~git20141128.5242b0-2+deb8u4")) flag++;
if (deb_check(release:"8.0", prefix:"libecal1.2-dev", reference:"3.12.9~git20141128.5242b0-2+deb8u4")) flag++;
if (deb_check(release:"8.0", prefix:"libedata-book-1.2-20", reference:"3.12.9~git20141128.5242b0-2+deb8u4")) flag++;
if (deb_check(release:"8.0", prefix:"libedata-book1.2-dev", reference:"3.12.9~git20141128.5242b0-2+deb8u4")) flag++;
if (deb_check(release:"8.0", prefix:"libedata-cal-1.2-23", reference:"3.12.9~git20141128.5242b0-2+deb8u4")) flag++;
if (deb_check(release:"8.0", prefix:"libedata-cal1.2-dev", reference:"3.12.9~git20141128.5242b0-2+deb8u4")) flag++;
if (deb_check(release:"8.0", prefix:"libedataserver-1.2-18", reference:"3.12.9~git20141128.5242b0-2+deb8u4")) flag++;
if (deb_check(release:"8.0", prefix:"libedataserver1.2-dev", reference:"3.12.9~git20141128.5242b0-2+deb8u4")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
