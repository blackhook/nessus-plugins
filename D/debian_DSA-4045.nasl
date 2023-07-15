#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-4045. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(104724);
  script_version("3.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2017-10699", "CVE-2017-9300");
  script_xref(name:"DSA", value:"4045");

  script_name(english:"Debian DSA-4045-1 : vlc - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several vulnerabilities have been found in VLC, the VideoLAN project's
media player. Processing malformed media files could lead to denial of
service and potentially the execution of arbitrary code."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/source-package/vlc"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/jessie/vlc"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/stretch/vlc"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.debian.org/security/2017/dsa-4045"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the vlc packages.

For the oldstable distribution (jessie), these problems have been
fixed in version 2.2.7-1~deb8u1.

For the stable distribution (stretch), these problems have been fixed
in version 2.2.7-1~deb9u1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:vlc");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:8.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:9.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/11/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/11/22");
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
if (deb_check(release:"8.0", prefix:"libvlc-dev", reference:"2.2.7-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libvlc5", reference:"2.2.7-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libvlccore-dev", reference:"2.2.7-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libvlccore8", reference:"2.2.7-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"vlc", reference:"2.2.7-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"vlc-data", reference:"2.2.7-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"vlc-dbg", reference:"2.2.7-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"vlc-nox", reference:"2.2.7-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"vlc-plugin-fluidsynth", reference:"2.2.7-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"vlc-plugin-jack", reference:"2.2.7-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"vlc-plugin-notify", reference:"2.2.7-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"vlc-plugin-pulse", reference:"2.2.7-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"vlc-plugin-samba", reference:"2.2.7-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"vlc-plugin-sdl", reference:"2.2.7-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"vlc-plugin-svg", reference:"2.2.7-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"vlc-plugin-zvbi", reference:"2.2.7-1~deb8u1")) flag++;
if (deb_check(release:"9.0", prefix:"libvlc-bin", reference:"2.2.7-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libvlc-dev", reference:"2.2.7-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libvlc5", reference:"2.2.7-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libvlccore-dev", reference:"2.2.7-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libvlccore8", reference:"2.2.7-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"vlc", reference:"2.2.7-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"vlc-bin", reference:"2.2.7-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"vlc-data", reference:"2.2.7-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"vlc-l10n", reference:"2.2.7-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"vlc-nox", reference:"2.2.7-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"vlc-plugin-access-extra", reference:"2.2.7-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"vlc-plugin-base", reference:"2.2.7-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"vlc-plugin-fluidsynth", reference:"2.2.7-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"vlc-plugin-jack", reference:"2.2.7-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"vlc-plugin-notify", reference:"2.2.7-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"vlc-plugin-qt", reference:"2.2.7-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"vlc-plugin-samba", reference:"2.2.7-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"vlc-plugin-sdl", reference:"2.2.7-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"vlc-plugin-skins2", reference:"2.2.7-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"vlc-plugin-svg", reference:"2.2.7-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"vlc-plugin-video-output", reference:"2.2.7-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"vlc-plugin-video-splitter", reference:"2.2.7-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"vlc-plugin-visualization", reference:"2.2.7-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"vlc-plugin-zvbi", reference:"2.2.7-1~deb9u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
