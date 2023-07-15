#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-1934-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(129408);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/11");

  script_cve_id("CVE-2018-7588", "CVE-2018-7589", "CVE-2018-7637", "CVE-2018-7638", "CVE-2018-7639", "CVE-2018-7640", "CVE-2018-7641", "CVE-2019-1010174");

  script_name(english:"Debian DLA-1934-1 : cimg security update");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several issues have been found in cimg, a powerful image processing
library.

CVE-2019-1010174 is related to a missing string sanitization on URLs,
which might result in a command injection when loading a special
crafted image.

The other CVEs are about heap-based buffer over-reads or double frees
when loading an image.

For Debian 8 'Jessie', these problems have been fixed in version
1.5.9+dfsg-1+deb8u1.

We recommend that you upgrade your cimg packages.

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2019/09/msg00030.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/jessie/cimg"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Upgrade the affected cimg-dev, cimg-doc, and cimg-examples packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:cimg-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:cimg-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:cimg-examples");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:8.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/03/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/09/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/09/30");
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
if (deb_check(release:"8.0", prefix:"cimg-dev", reference:"1.5.9+dfsg-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"cimg-doc", reference:"1.5.9+dfsg-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"cimg-examples", reference:"1.5.9+dfsg-1+deb8u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
