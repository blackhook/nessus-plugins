#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-1042-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(102040);
  script_version("3.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/11");

  script_cve_id("CVE-2017-9122", "CVE-2017-9123", "CVE-2017-9124", "CVE-2017-9125", "CVE-2017-9126", "CVE-2017-9127", "CVE-2017-9128");

  script_name(english:"Debian DLA-1042-1 : libquicktime security update");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"CVE-2017-9122

The quicktime_read_moov function in moov.c in libquicktime 1.2.4
allows remote attackers to cause a denial of service (infinite loop
and CPU consumption) via a crafted mp4 file.

CVE-2017-9123

The lqt_frame_duration function in lqt_quicktime.c in libquicktime
1.2.4 allows remote attackers to cause a denial of service (invalid
memory read and application crash) via a crafted mp4 file.

CVE-2017-9124

The quicktime_match_32 function in util.c in libquicktime 1.2.4 allows
remote attackers to cause a denial of service (NULL pointer
dereference and application crash) via a crafted mp4 file.

CVE-2017-9125

The lqt_frame_duration function in lqt_quicktime.c in libquicktime
1.2.4 allows remote attackers to cause a denial of service (heap-based
buffer over-read) via a crafted mp4 file.

CVE-2017-9126

The quicktime_read_dref_table function in dref.c in libquicktime 1.2.4
allows remote attackers to cause a denial of service (heap-based
buffer overflow and application crash) via a crafted mp4 file.

CVE-2017-9127

The quicktime_user_atoms_read_atom function in useratoms.c in
libquicktime 1.2.4 allows remote attackers to cause a denial of
service (heap-based buffer overflow and application crash) via a
crafted mp4 file.

CVE-2017-9128

The quicktime_video_width function in lqt_quicktime.c in libquicktime
1.2.4 allows remote attackers to cause a denial of service (heap-based
buffer over-read and application crash) via a crafted mp4 file.

For Debian 7 'Wheezy', these problems have been fixed in version
2:1.2.4-3+deb7u2.

We recommend that you upgrade your libquicktime packages.

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2017/07/msg00036.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/wheezy/libquicktime"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libquicktime-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libquicktime-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libquicktime2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:quicktime-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:quicktime-x11utils");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:7.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/07/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/07/31");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017-2021 Tenable Network Security, Inc.");
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
if (deb_check(release:"7.0", prefix:"libquicktime-dev", reference:"2:1.2.4-3+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"libquicktime-doc", reference:"2:1.2.4-3+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"libquicktime2", reference:"2:1.2.4-3+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"quicktime-utils", reference:"2:1.2.4-3+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"quicktime-x11utils", reference:"2:1.2.4-3+deb7u2")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
