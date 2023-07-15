#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-1065-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(102785);
  script_version("3.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/11");

  script_cve_id("CVE-2017-11568", "CVE-2017-11569", "CVE-2017-11571", "CVE-2017-11572", "CVE-2017-11574", "CVE-2017-11575", "CVE-2017-11576", "CVE-2017-11577");

  script_name(english:"Debian DLA-1065-1 : fontforge security update");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"FontForge is vulnerable to heap-based buffer over-read in several
functions, resulting in DoS or code execution via a crafted otf file :

For Debian 7 'Wheezy', these problems have been fixed in version
0.0.20120101+git-2+deb7u1.

We recommend that you upgrade your fontforge packages.

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2017/08/msg00017.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/wheezy/fontforge"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fontforge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fontforge-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fontforge-nox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libfontforge-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libfontforge1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libgdraw4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:python-fontforge");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:7.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/08/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/08/28");
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
if (deb_check(release:"7.0", prefix:"fontforge", reference:"0.0.20120101+git-2+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"fontforge-dbg", reference:"0.0.20120101+git-2+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"fontforge-nox", reference:"0.0.20120101+git-2+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libfontforge-dev", reference:"0.0.20120101+git-2+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libfontforge1", reference:"0.0.20120101+git-2+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libgdraw4", reference:"0.0.20120101+git-2+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"python-fontforge", reference:"0.0.20120101+git-2+deb7u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
