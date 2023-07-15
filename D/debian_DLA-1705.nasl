#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-1705-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(122620);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/11");

  script_cve_id("CVE-2017-11332", "CVE-2017-11358", "CVE-2017-11359", "CVE-2017-15371");

  script_name(english:"Debian DLA-1705-1 : sox security update");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Multiple vulnerabilities have been discovered in SoX (Sound eXchange),
a sound processing program :

CVE-2017-11332

The startread function (wav.c) is affected by a divide-by-zero
vulnerability when processing WAV file with zero channel count. This
flaw might be leveraged by remote attackers using a crafted WAV file
to perform denial of service (application crash).

CVE-2017-11358

The read_samples function (hcom.c) is affected by an invalid memory
read vulnerability when processing HCOM files with invalid
dictionnaries. This flaw might be leveraged by remote attackers using
a crafted HCOM file to perform denial of service (application crash).

CVE-2017-11359

The wavwritehdr function (wav.c) is affected by a divide-by-zero
vulnerability when processing WAV files with invalid channel count
over 16 bits. This flaw might be leveraged by remote attackers using a
crafted WAV file to perform denial of service (application crash).

CVE-2017-15371

The sox_append_comment() function (formats.c) is vulnerable to a
reachable assertion when processing FLAC files with metadata declaring
more comments than provided. This flaw might be leveraged by remote
attackers using crafted FLAC data to perform denial of service
(application crash).

For Debian 8 'Jessie', these problems have been fixed in version
14.4.1-5+deb8u3.

We recommend that you upgrade your sox packages.

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2019/03/msg00007.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/jessie/sox"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libsox-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libsox-fmt-all");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libsox-fmt-alsa");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libsox-fmt-ao");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libsox-fmt-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libsox-fmt-mp3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libsox-fmt-oss");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libsox-fmt-pulse");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libsox2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:sox");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:8.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/07/31");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/03/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/03/06");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2019-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (deb_check(release:"8.0", prefix:"libsox-dev", reference:"14.4.1-5+deb8u3")) flag++;
if (deb_check(release:"8.0", prefix:"libsox-fmt-all", reference:"14.4.1-5+deb8u3")) flag++;
if (deb_check(release:"8.0", prefix:"libsox-fmt-alsa", reference:"14.4.1-5+deb8u3")) flag++;
if (deb_check(release:"8.0", prefix:"libsox-fmt-ao", reference:"14.4.1-5+deb8u3")) flag++;
if (deb_check(release:"8.0", prefix:"libsox-fmt-base", reference:"14.4.1-5+deb8u3")) flag++;
if (deb_check(release:"8.0", prefix:"libsox-fmt-mp3", reference:"14.4.1-5+deb8u3")) flag++;
if (deb_check(release:"8.0", prefix:"libsox-fmt-oss", reference:"14.4.1-5+deb8u3")) flag++;
if (deb_check(release:"8.0", prefix:"libsox-fmt-pulse", reference:"14.4.1-5+deb8u3")) flag++;
if (deb_check(release:"8.0", prefix:"libsox2", reference:"14.4.1-5+deb8u3")) flag++;
if (deb_check(release:"8.0", prefix:"sox", reference:"14.4.1-5+deb8u3")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
