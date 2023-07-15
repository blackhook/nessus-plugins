#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-2660-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include("compat.inc");

if (description)
{
  script_id(149488);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/05/18");

  script_cve_id("CVE-2021-20204");

  script_name(english:"Debian DLA-2660-1 : libgetdata security update");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"One security issue has been discovered in libgetdata

CVE-2021-20204

A heap memory corruption problem (use after free) can be triggered
when processing maliciously crafted dirfile databases. This degrades
the confidentiality, integrity and availability of third-party
software that uses libgetdata as a library.

For Debian 9 stretch, this problem has been fixed in version
0.9.4-1+deb9u1.

We recommend that you upgrade your libgetdata packages.

For the detailed security status of libgetdata please refer to its
security tracker page at:
https://security-tracker.debian.org/tracker/libgetdata

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2021/05/msg00015.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/stretch/libgetdata"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/source-package/libgetdata"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libf95getdata6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libfgetdata5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libgetdata++6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libgetdata-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libgetdata-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libgetdata-perl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libgetdata-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libgetdata7");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:python-pygetdata");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:python3-pygetdata");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:9.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/05/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/05/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/05/14");
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
if (deb_check(release:"9.0", prefix:"libf95getdata6", reference:"0.9.4-1+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libfgetdata5", reference:"0.9.4-1+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libgetdata++6", reference:"0.9.4-1+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libgetdata-dev", reference:"0.9.4-1+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libgetdata-doc", reference:"0.9.4-1+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libgetdata-perl", reference:"0.9.4-1+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libgetdata-tools", reference:"0.9.4-1+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libgetdata7", reference:"0.9.4-1+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"python-pygetdata", reference:"0.9.4-1+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"python3-pygetdata", reference:"0.9.4-1+deb9u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
