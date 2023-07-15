#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-2675-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include("compat.inc");

if (description)
{
  script_id(150272);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/06/04");

  script_name(english:"Debian DLA-2675-1 : caribou regression update");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"It was found that the fix for CVE-2020-25712 in the Xorg X server,
addressed in DLA-2486-1, caused a regression in caribou, making it
crash whenever special (shifted) characters were entered.

For Debian 9 stretch, this problem has been fixed in version
0.4.21-1+deb9u1.

We recommend that you upgrade your caribou packages.

For the detailed security status of caribou please refer to its
security tracker page at:
https://security-tracker.debian.org/tracker/caribou

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2021/06/msg00003.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/stretch/caribou"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/source-package/caribou"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade the affected packages.");
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:caribou");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:caribou-antler");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:gir1.2-caribou-1.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libcaribou-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libcaribou-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libcaribou-gtk-module");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libcaribou-gtk3-module");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libcaribou0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:9.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/06/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/06/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/06/04");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (deb_check(release:"9.0", prefix:"caribou", reference:"0.4.21-1+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"caribou-antler", reference:"0.4.21-1+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"gir1.2-caribou-1.0", reference:"0.4.21-1+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libcaribou-common", reference:"0.4.21-1+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libcaribou-dev", reference:"0.4.21-1+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libcaribou-gtk-module", reference:"0.4.21-1+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libcaribou-gtk3-module", reference:"0.4.21-1+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libcaribou0", reference:"0.4.21-1+deb9u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
