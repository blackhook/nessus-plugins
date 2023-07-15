#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-617-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(93415);
  script_version("2.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/11");

  script_cve_id("CVE-2015-8915", "CVE-2016-7166");

  script_name(english:"Debian DLA-617-1 : libarchive security update");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several security vulnerabilities have been discovered in libarchive, a
multi-format archive and compression library. An attacker could take
advantage of these flaws to cause an out of bounds read or a denial of
service against an application using the libarchive12 library using a
carefully crafted input file.

CVE-2015-8915

Paris Zoumpouloglou of Project Zero labs discovered a flaw in
libarchive bsdtar. Using a crafted file bsdtar can perform an
out-of-bounds memory read which will lead to a SEGFAULT.

CVE-2016-7166

Alexander Cherepanov discovered a flaw in libarchive compression
handling. Using a crafted gzip file, one can get libarchive to invoke
an infinite chain of gzip compressors until all the memory has been
exhausted or another resource limit kicks in.

For Debian 7 'Wheezy', these problems have been fixed in version
3.0.4-3+wheezy3.

We recommend that you upgrade your libarchive packages.

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2016/09/msg00010.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/wheezy/libarchive"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:bsdcpio");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:bsdtar");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libarchive-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libarchive12");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:7.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/09/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/09/12");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016-2021 Tenable Network Security, Inc.");
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
if (deb_check(release:"7.0", prefix:"bsdcpio", reference:"3.0.4-3+wheezy3")) flag++;
if (deb_check(release:"7.0", prefix:"bsdtar", reference:"3.0.4-3+wheezy3")) flag++;
if (deb_check(release:"7.0", prefix:"libarchive-dev", reference:"3.0.4-3+wheezy3")) flag++;
if (deb_check(release:"7.0", prefix:"libarchive12", reference:"3.0.4-3+wheezy3")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
