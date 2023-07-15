#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-2302-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(139245);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/13");

  script_cve_id("CVE-2018-1152", "CVE-2018-14498", "CVE-2020-13790", "CVE-2020-14152");
  script_xref(name:"TRA", value:"TRA-2018-17");

  script_name(english:"Debian DLA-2302-1 : libjpeg-turbo security update");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"Several vulnerabilities were fixed in libjpeg-turbo, a widely used
library for handling JPEG files.

CVE-2018-1152

Denial of service vulnerability caused by a divide by zero when
processing a crafted BMP image in TJBench.

CVE-2018-14498

Denial of service (heap-based buffer over-read and application crash)
via a crafted 8-bit BMP in which one or more of the color indices is
out of range for the number of palette entries.

CVE-2020-13790

Heap-based buffer over-read via a malformed PPM input file.

CVE-2020-14152

jpeg_mem_available() did not honor the max_memory_to_use setting,
possibly causing excessive memory consumption.

For Debian 9 stretch, these problems have been fixed in version
1:1.5.1-2+deb9u1.

We recommend that you upgrade your libjpeg-turbo packages.

For the detailed security status of libjpeg-turbo please refer to its
security tracker page at:
https://security-tracker.debian.org/tracker/libjpeg-turbo

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2020/07/msg00033.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/stretch/libjpeg-turbo"
  );
  # https://security-tracker.debian.org/tracker/source-package/libjpeg-turbo
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?9774e827"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.tenable.com/security/research/tra-2018-17"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-14152");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libjpeg-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libjpeg-turbo-progs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libjpeg62-turbo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libjpeg62-turbo-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libturbojpeg0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libturbojpeg0-dev");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:9.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/06/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/07/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/08/03");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2020-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (deb_check(release:"9.0", prefix:"libjpeg-dev", reference:"1:1.5.1-2+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libjpeg-turbo-progs", reference:"1:1.5.1-2+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libjpeg62-turbo", reference:"1:1.5.1-2+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libjpeg62-turbo-dev", reference:"1:1.5.1-2+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libturbojpeg0", reference:"1:1.5.1-2+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libturbojpeg0-dev", reference:"1:1.5.1-2+deb9u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
