#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-2640-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(149009);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/04/29");

  script_cve_id("CVE-2021-3497");

  script_name(english:"Debian DLA-2640-1 : gst-plugins-good1.0 security update");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"A use-after-free vulnerability was found in the Matroska plugin of the
the GStreamer media framework, which may result in denial of service
or potentially the execution of arbitrary code if a malformed media
file is opened.

For Debian 9 stretch, this problem has been fixed in version
1.10.4-1+deb9u1.

We recommend that you upgrade your gst-plugins-good1.0 packages.

For the detailed security status of gst-plugins-good1.0 please refer
to its security tracker page at:
https://security-tracker.debian.org/tracker/gst-plugins-good1.0

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2021/04/msg00027.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/stretch/gst-plugins-good1.0"
  );
  # https://security-tracker.debian.org/tracker/source-package/gst-plugins-good1.0
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?91533ee1"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-3497");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:gstreamer1.0-plugins-good");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:gstreamer1.0-plugins-good-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:gstreamer1.0-plugins-good-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:gstreamer1.0-pulseaudio");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:9.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/04/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/04/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/04/27");
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
if (deb_check(release:"9.0", prefix:"gstreamer1.0-plugins-good", reference:"1.10.4-1+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"gstreamer1.0-plugins-good-dbg", reference:"1.10.4-1+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"gstreamer1.0-plugins-good-doc", reference:"1.10.4-1+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"gstreamer1.0-pulseaudio", reference:"1.10.4-1+deb9u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
