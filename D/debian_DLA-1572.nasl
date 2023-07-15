#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-1572-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(118839);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/11");

  script_cve_id("CVE-2018-16845");

  script_name(english:"Debian DLA-1572-1 : nginx security update");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"It was discovered that there was a denial of service (DoS)
vulnerability in the nginx web/proxy server.

As there was no validation for the size of a 64-bit atom in an MP4
file, this could have led to a CPU hog when the size was 0, or various
other problems due to integer underflow when the calculating atom data
size, including segmentation faults or even worker-process memory
disclosure.

For Debian 8 'Jessie', this issue has been fixed in nginx version
1.6.2-5+deb8u6.

We recommend that you upgrade your nginx packages.

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2018/11/msg00010.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/jessie/nginx"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nginx");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nginx-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nginx-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nginx-extras");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nginx-extras-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nginx-full");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nginx-full-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nginx-light");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nginx-light-dbg");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:8.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/11/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/11/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/11/09");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2018-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (deb_check(release:"8.0", prefix:"nginx", reference:"1.6.2-5+deb8u6")) flag++;
if (deb_check(release:"8.0", prefix:"nginx-common", reference:"1.6.2-5+deb8u6")) flag++;
if (deb_check(release:"8.0", prefix:"nginx-doc", reference:"1.6.2-5+deb8u6")) flag++;
if (deb_check(release:"8.0", prefix:"nginx-extras", reference:"1.6.2-5+deb8u6")) flag++;
if (deb_check(release:"8.0", prefix:"nginx-extras-dbg", reference:"1.6.2-5+deb8u6")) flag++;
if (deb_check(release:"8.0", prefix:"nginx-full", reference:"1.6.2-5+deb8u6")) flag++;
if (deb_check(release:"8.0", prefix:"nginx-full-dbg", reference:"1.6.2-5+deb8u6")) flag++;
if (deb_check(release:"8.0", prefix:"nginx-light", reference:"1.6.2-5+deb8u6")) flag++;
if (deb_check(release:"8.0", prefix:"nginx-light-dbg", reference:"1.6.2-5+deb8u6")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
