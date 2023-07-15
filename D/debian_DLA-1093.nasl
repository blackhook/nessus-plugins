#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-1093-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(103093);
  script_version("3.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/11");

  script_cve_id("CVE-2017-11335", "CVE-2017-12944", "CVE-2017-13726", "CVE-2017-13727");

  script_name(english:"Debian DLA-1093-1 : tiff security update");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several vulnerabilities have been discovered in the Tag Image File
Format (TIFF) library and its associated tools.

CVE-2017-11335

A heap based buffer overflow via a PlanarConfig=Contig image, which
causes an out-of-bounds write (related to the ZIPDecode function). A
crafted input may lead to a remote denial of service attack or an
arbitrary code execution attack.

CVE-2017-12944

A mishandling of memory allocation for short files allows attackers to
cause a denial of service (allocation failure and application crash)
during a tiff2pdf invocation.

CVE-2017-13726

A reachable assertion abort allows a crafted input to lead to a remote
denial of service attack.

CVE-2017-13727

A reachable assertion abort allows a crafted input to lead to a remote
denial of service attack.

For Debian 7 'Wheezy', these problems have been fixed in version
4.0.2-6+deb7u16.

We recommend that you upgrade your tiff packages.

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2017/09/msg00010.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/wheezy/tiff"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libtiff-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libtiff-opengl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libtiff-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libtiff5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libtiff5-alt-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libtiff5-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libtiffxx5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:7.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/09/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/09/11");
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
if (deb_check(release:"7.0", prefix:"libtiff-doc", reference:"4.0.2-6+deb7u16")) flag++;
if (deb_check(release:"7.0", prefix:"libtiff-opengl", reference:"4.0.2-6+deb7u16")) flag++;
if (deb_check(release:"7.0", prefix:"libtiff-tools", reference:"4.0.2-6+deb7u16")) flag++;
if (deb_check(release:"7.0", prefix:"libtiff5", reference:"4.0.2-6+deb7u16")) flag++;
if (deb_check(release:"7.0", prefix:"libtiff5-alt-dev", reference:"4.0.2-6+deb7u16")) flag++;
if (deb_check(release:"7.0", prefix:"libtiff5-dev", reference:"4.0.2-6+deb7u16")) flag++;
if (deb_check(release:"7.0", prefix:"libtiffxx5", reference:"4.0.2-6+deb7u16")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
