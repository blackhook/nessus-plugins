#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-1554-2. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(118407);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/11");

  script_name(english:"Debian DLA-1554-2 : 389-ds-base regression update");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"A regression was found in the recent security update for 389-ds-base
(the 389 Directory Server), announced as DLA-1554-2, caused by an
incomplete fix for CVE-2018-14648. The regression caused the server to
crash when processing requests with empty attributes.

For Debian 8 'Jessie', this problem has been fixed in version
1.3.3.5-4+deb8u5.

We recommend that you upgrade your 389-ds-base packages.

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2018/10/msg00016.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/jessie/389-ds-base"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade the affected packages.");
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:389-ds");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:389-ds-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:389-ds-base-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:389-ds-base-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:389-ds-base-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:389-ds-base-libs-dbg");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:8.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2018/10/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/10/26");
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
if (deb_check(release:"8.0", prefix:"389-ds", reference:"1.3.3.5-4+deb8u5")) flag++;
if (deb_check(release:"8.0", prefix:"389-ds-base", reference:"1.3.3.5-4+deb8u5")) flag++;
if (deb_check(release:"8.0", prefix:"389-ds-base-dbg", reference:"1.3.3.5-4+deb8u5")) flag++;
if (deb_check(release:"8.0", prefix:"389-ds-base-dev", reference:"1.3.3.5-4+deb8u5")) flag++;
if (deb_check(release:"8.0", prefix:"389-ds-base-libs", reference:"1.3.3.5-4+deb8u5")) flag++;
if (deb_check(release:"8.0", prefix:"389-ds-base-libs-dbg", reference:"1.3.3.5-4+deb8u5")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
