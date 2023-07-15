#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-2246-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(137416);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/11");

  script_cve_id("CVE-2020-13696");

  script_name(english:"Debian DLA-2246-1 : xawtv security update");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"An issue was discovered in LinuxTV xawtv before 3.107. The function
dev_open() in v4l-conf.c does not perform sufficient checks to prevent
an unprivileged caller of the program from opening unintended
filesystem paths. This allows a local attacker with access to the
v4l-conf setuid-root program to test for the existence of arbitrary
files and to trigger an open on arbitrary files with mode O_RDWR. To
achieve this, relative path components need to be added to the device
path, as demonstrated by a v4l-conf -c /dev/../root/.bash_history
command.

For Debian 8 'Jessie', this problem has been fixed in version
3.103-3+deb8u1.

We recommend that you upgrade your xawtv packages.

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2020/06/msg00018.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/jessie/xawtv"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-13696");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:alevtd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fbtv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:pia");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:radio");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scantv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:streamer");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ttv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:v4l-conf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:webcam");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:xawtv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:xawtv-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:xawtv-plugin-qt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:xawtv-plugins");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:xawtv-tools");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:8.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/06/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/06/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/06/17");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2020-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (deb_check(release:"8.0", prefix:"alevtd", reference:"3.103-3+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"fbtv", reference:"3.103-3+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"pia", reference:"3.103-3+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"radio", reference:"3.103-3+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"scantv", reference:"3.103-3+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"streamer", reference:"3.103-3+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"ttv", reference:"3.103-3+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"v4l-conf", reference:"3.103-3+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"webcam", reference:"3.103-3+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"xawtv", reference:"3.103-3+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"xawtv-dbg", reference:"3.103-3+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"xawtv-plugin-qt", reference:"3.103-3+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"xawtv-plugins", reference:"3.103-3+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"xawtv-tools", reference:"3.103-3+deb8u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_note(port:0, extra:deb_report_get());
  else security_note(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
