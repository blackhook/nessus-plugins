#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-2528-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(145208);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/20");

  script_name(english:"Debian DLA-2528-1 : gst-plugins-bad1.0 security update");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"Andrew Wesie discovered a buffer overflow in the H264 support of the
GStreamer multimedia framework, which could potentially result in the
execution of arbitrary code.

For Debian 9 stretch, this problem has been fixed in version
1.10.4-1+deb9u1.

We recommend that you upgrade your gst-plugins-bad1.0 packages.

For the detailed security status of gst-plugins-bad1.0 please refer to
its security tracker page at:
https://security-tracker.debian.org/tracker/gst-plugins-bad1.0

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2021/01/msg00016.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/stretch/gst-plugins-bad1.0"
  );
  # https://security-tracker.debian.org/tracker/source-package/gst-plugins-bad1.0
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?7460d4a1"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade the affected packages.");
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:gir1.2-gst-plugins-bad-1.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:gstreamer1.0-plugins-bad");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:gstreamer1.0-plugins-bad-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:gstreamer1.0-plugins-bad-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libgstreamer-plugins-bad1.0-0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libgstreamer-plugins-bad1.0-dev");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:9.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/01/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/01/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/01/20");
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
if (deb_check(release:"9.0", prefix:"gir1.2-gst-plugins-bad-1.0", reference:"1.10.4-1+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"gstreamer1.0-plugins-bad", reference:"1.10.4-1+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"gstreamer1.0-plugins-bad-dbg", reference:"1.10.4-1+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"gstreamer1.0-plugins-bad-doc", reference:"1.10.4-1+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libgstreamer-plugins-bad1.0-0", reference:"1.10.4-1+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libgstreamer-plugins-bad1.0-dev", reference:"1.10.4-1+deb9u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
