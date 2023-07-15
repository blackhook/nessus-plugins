#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-4704. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(137573);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/06/22");

  script_cve_id("CVE-2020-13428");
  script_xref(name:"DSA", value:"4704");

  script_name(english:"Debian DSA-4704-1 : vlc - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"A vulnerability was discovered in the VLC media player, which could
result in the execution of arbitrary code or denial of service if a
malformed video file is opened."
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
    value:"https://packages.debian.org/source/buster/vlc"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.debian.org/security/2020/dsa-4704"
  );
  script_set_attribute(
    attribute:"solution",
    value:
"Upgrade the vlc packages.

For the oldstable distribution (stretch), this problem has been fixed
in version 3.0.11-0+deb9u1.

For the stable distribution (buster), this problem has been fixed in
version 3.0.11-0+deb10u1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:vlc");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:10.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:9.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/06/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/06/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/06/18");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (deb_check(release:"10.0", prefix:"libvlc-bin", reference:"3.0.11-0+deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"libvlc-dev", reference:"3.0.11-0+deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"libvlc5", reference:"3.0.11-0+deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"libvlccore-dev", reference:"3.0.11-0+deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"libvlccore9", reference:"3.0.11-0+deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"vlc", reference:"3.0.11-0+deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"vlc-bin", reference:"3.0.11-0+deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"vlc-data", reference:"3.0.11-0+deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"vlc-l10n", reference:"3.0.11-0+deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"vlc-plugin-access-extra", reference:"3.0.11-0+deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"vlc-plugin-base", reference:"3.0.11-0+deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"vlc-plugin-fluidsynth", reference:"3.0.11-0+deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"vlc-plugin-jack", reference:"3.0.11-0+deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"vlc-plugin-notify", reference:"3.0.11-0+deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"vlc-plugin-qt", reference:"3.0.11-0+deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"vlc-plugin-samba", reference:"3.0.11-0+deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"vlc-plugin-skins2", reference:"3.0.11-0+deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"vlc-plugin-svg", reference:"3.0.11-0+deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"vlc-plugin-video-output", reference:"3.0.11-0+deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"vlc-plugin-video-splitter", reference:"3.0.11-0+deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"vlc-plugin-visualization", reference:"3.0.11-0+deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"vlc-plugin-zvbi", reference:"3.0.11-0+deb10u1")) flag++;
if (deb_check(release:"9.0", prefix:"libvlc-bin", reference:"3.0.11-0+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libvlc-dev", reference:"3.0.11-0+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libvlc5", reference:"3.0.11-0+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libvlccore-dev", reference:"3.0.11-0+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libvlccore8", reference:"3.0.11-0+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"vlc", reference:"3.0.11-0+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"vlc-bin", reference:"3.0.11-0+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"vlc-data", reference:"3.0.11-0+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"vlc-l10n", reference:"3.0.11-0+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"vlc-nox", reference:"3.0.11-0+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"vlc-plugin-access-extra", reference:"3.0.11-0+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"vlc-plugin-base", reference:"3.0.11-0+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"vlc-plugin-fluidsynth", reference:"3.0.11-0+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"vlc-plugin-jack", reference:"3.0.11-0+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"vlc-plugin-notify", reference:"3.0.11-0+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"vlc-plugin-qt", reference:"3.0.11-0+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"vlc-plugin-samba", reference:"3.0.11-0+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"vlc-plugin-sdl", reference:"3.0.11-0+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"vlc-plugin-skins2", reference:"3.0.11-0+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"vlc-plugin-svg", reference:"3.0.11-0+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"vlc-plugin-video-output", reference:"3.0.11-0+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"vlc-plugin-video-splitter", reference:"3.0.11-0+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"vlc-plugin-visualization", reference:"3.0.11-0+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"vlc-plugin-zvbi", reference:"3.0.11-0+deb9u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
