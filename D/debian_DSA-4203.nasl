#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-4203. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(109902);
  script_version("1.4");
  script_cvs_date("Date: 2018/11/13 12:30:47");

  script_cve_id("CVE-2017-17670");
  script_xref(name:"DSA", value:"4203");

  script_name(english:"Debian DSA-4203-1 : vlc - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Hans Jerry Illikainen discovered a type conversion vulnerability in
the MP4 demuxer of the VLC media player, which could result in the
execution of arbitrary code if a malformed media file is played.

This update upgrades VLC in stretch to the new 3.x release series (as
security fixes couldn't be sensibly backported to the 2.x series). In
addition two packages needed to be rebuild to ensure compatibility
with VLC 3; phonon-backend-vlc (0.9.0-2+deb9u1) and goldencheetah
(4.0.0~DEV1607-2+deb9u1).

VLC in jessie cannot be migrated to version 3 due to incompatible
library changes with reverse dependencies and is thus now declared
end-of-life for jessie. We recommend to upgrade to stretch or pick a
different media player if that's not an option."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/source-package/vlc"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/stretch/vlc"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.debian.org/security/2018/dsa-4203"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the vlc packages.

For the stable distribution (stretch), this problem has been fixed in
version 3.0.2-0+deb9u1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:vlc");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:9.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2018/05/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/05/18");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2018 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (deb_check(release:"9.0", prefix:"libvlc-bin", reference:"3.0.2-0+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libvlc-dev", reference:"3.0.2-0+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libvlc5", reference:"3.0.2-0+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libvlccore-dev", reference:"3.0.2-0+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libvlccore8", reference:"3.0.2-0+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"vlc", reference:"3.0.2-0+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"vlc-bin", reference:"3.0.2-0+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"vlc-data", reference:"3.0.2-0+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"vlc-l10n", reference:"3.0.2-0+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"vlc-nox", reference:"3.0.2-0+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"vlc-plugin-access-extra", reference:"3.0.2-0+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"vlc-plugin-base", reference:"3.0.2-0+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"vlc-plugin-fluidsynth", reference:"3.0.2-0+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"vlc-plugin-jack", reference:"3.0.2-0+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"vlc-plugin-notify", reference:"3.0.2-0+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"vlc-plugin-qt", reference:"3.0.2-0+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"vlc-plugin-samba", reference:"3.0.2-0+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"vlc-plugin-sdl", reference:"3.0.2-0+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"vlc-plugin-skins2", reference:"3.0.2-0+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"vlc-plugin-svg", reference:"3.0.2-0+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"vlc-plugin-video-output", reference:"3.0.2-0+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"vlc-plugin-video-splitter", reference:"3.0.2-0+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"vlc-plugin-visualization", reference:"3.0.2-0+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"vlc-plugin-zvbi", reference:"3.0.2-0+deb9u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
