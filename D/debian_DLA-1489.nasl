#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-1489-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(112228);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/11");

  script_cve_id("CVE-2018-10873");

  script_name(english:"Debian DLA-1489-1 : spice-gtk security update");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"A vulnerability was discovered in SPICE before version 0.14.1 where
the generated code used for demarshalling messages lacked sufficient
bounds checks. A malicious client or server, after authentication,
could send specially crafted messages to its peer which would result
in a crash or, potentially, other impacts.

The issue has been fixed by upstream by bailing out with an error if
the pointer to the start of some message data is strictly greater than
the pointer to the end of the message data.

The above issue and fix have already been announced for the 'spice'
Debian package (as DLA-1486-1 [1]). This announcement is about the
'spice-gtk' Debian package (which ships some copies of code from the
'spice' package, where the fix of this issue had to be applied).

[1] https://lists.debian.org/debian-lts-announce/2018/08/msg00037.html

For Debian 8 'Jessie', this problem has been fixed in version
0.25-1+deb8u1.

We recommend that you upgrade your spice-gtk packages.

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2018/08/msg00037.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2018/08/msg00038.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/jessie/spice-gtk"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:gir1.2-spice-client-glib-2.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:gir1.2-spice-client-gtk-2.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:gir1.2-spice-client-gtk-3.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libspice-client-glib-2.0-8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libspice-client-glib-2.0-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libspice-client-gtk-2.0-4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libspice-client-gtk-2.0-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libspice-client-gtk-3.0-4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libspice-client-gtk-3.0-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:python-spice-client-gtk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:spice-client-glib-usb-acl-helper");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:spice-client-gtk");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:8.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2018/08/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/09/04");
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
if (deb_check(release:"8.0", prefix:"gir1.2-spice-client-glib-2.0", reference:"0.25-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"gir1.2-spice-client-gtk-2.0", reference:"0.25-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"gir1.2-spice-client-gtk-3.0", reference:"0.25-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libspice-client-glib-2.0-8", reference:"0.25-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libspice-client-glib-2.0-dev", reference:"0.25-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libspice-client-gtk-2.0-4", reference:"0.25-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libspice-client-gtk-2.0-dev", reference:"0.25-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libspice-client-gtk-3.0-4", reference:"0.25-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libspice-client-gtk-3.0-dev", reference:"0.25-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"python-spice-client-gtk", reference:"0.25-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"spice-client-glib-usb-acl-helper", reference:"0.25-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"spice-client-gtk", reference:"0.25-1+deb8u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
