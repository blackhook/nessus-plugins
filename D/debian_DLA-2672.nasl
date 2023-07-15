#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-2672-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include("compat.inc");

if (description)
{
  script_id(150173);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/06/09");

  script_cve_id("CVE-2018-25009", "CVE-2018-25010", "CVE-2018-25011", "CVE-2018-25012", "CVE-2018-25013", "CVE-2018-25014", "CVE-2020-36328", "CVE-2020-36329", "CVE-2020-36330", "CVE-2020-36331");

  script_name(english:"Debian DLA-2672-1 : libwebp security update");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"Multiple security issues have been discovered in libwebp

CVE-2018-25009

An out-of-bounds read was found in function WebPMuxCreateInternal. The
highest threat from this vulnerability is to data confidentiality and
to the service availability.

CVE-2018-25010

An out-of-bounds read was found in function ApplyFilter. The highest
threat from this vulnerability is to data confidentiality and to the
service availability.

CVE-2018-25011

A heap-based buffer overflow was found in PutLE16(). The highest
threat from this vulnerability is to data confidentiality and
integrity as well as system availability.

CVE-2018-25012

An out-of-bounds read was found in function WebPMuxCreateInternal. The
highest threat from this vulnerability is to data confidentiality and
to the service availability.

CVE-2018-25013

An out-of-bounds read was found in function ShiftBytes. The highest
threat from this vulnerability is to data confidentiality and to the
service availability.

CVE-2018-25014

An unitialized variable is used in function ReadSymbol. The highest
threat from this vulnerability is to data confidentiality and
integrity as well as system availability.

CVE-2020-36328

A heap-based buffer overflow in function WebPDecodeRGBInto is possible
due to an invalid check for buffer size. The highest threat from this
vulnerability is to data confidentiality and integrity as well as
system availability.

CVE-2020-36329

A use-after-free was found due to a thread being killed too early. The
highest threat from this vulnerability is to data confidentiality and
integrity as well as system availability.

CVE-2020-36330

An out-of-bounds read was found in function ChunkVerifyAndAssign. The
highest threat from this vulnerability is to data confidentiality and
to the service availability.

CVE-2020-36331

An out-of-bounds read was found in function ChunkAssignData. The
highest threat from this vulnerability is to data confidentiality and
to the service availability.

For Debian 9 stretch, these problems have been fixed in version
0.5.2-1+deb9u1.

We recommend that you upgrade your libwebp packages.

For the detailed security status of libwebp please refer to its
security tracker page at:
https://security-tracker.debian.org/tracker/libwebp

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2021/06/msg00005.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/stretch/libwebp"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/source-package/libwebp"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-36329");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libwebp-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libwebp6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libwebpdemux2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libwebpmux2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:webp");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:9.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/05/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/06/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/06/03");
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
if (deb_check(release:"9.0", prefix:"libwebp-dev", reference:"0.5.2-1+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libwebp6", reference:"0.5.2-1+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libwebpdemux2", reference:"0.5.2-1+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libwebpmux2", reference:"0.5.2-1+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"webp", reference:"0.5.2-1+deb9u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
