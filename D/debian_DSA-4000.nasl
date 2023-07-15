#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-4000. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(103882);
  script_version("3.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2017-12176", "CVE-2017-12177", "CVE-2017-12178", "CVE-2017-12179", "CVE-2017-12180", "CVE-2017-12181", "CVE-2017-12182", "CVE-2017-12183", "CVE-2017-12184", "CVE-2017-12185", "CVE-2017-12186", "CVE-2017-12187", "CVE-2017-13721", "CVE-2017-13723");
  script_xref(name:"DSA", value:"4000");

  script_name(english:"Debian DSA-4000-1 : xorg-server - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several vulnerabilities have been discovered in the X.Org X server. An
attacker who's able to connect to an X server could cause a denial of
service or potentially the execution of arbitrary code."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/jessie/xorg-server"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/stretch/xorg-server"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.debian.org/security/2017/dsa-4000"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the xorg-server packages.

For the oldstable distribution (jessie), these problems have been
fixed in version 2:1.16.4-1+deb8u2.

For the stable distribution (stretch), these problems have been fixed
in version 2:1.19.2-1+deb9u2."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:xorg-server");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:8.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:9.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/10/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/10/18");
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
if (deb_check(release:"8.0", prefix:"xdmx", reference:"2:1.16.4-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"xdmx-tools", reference:"2:1.16.4-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"xnest", reference:"2:1.16.4-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"xorg-server-source", reference:"2:1.16.4-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"xserver-common", reference:"2:1.16.4-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"xserver-xephyr", reference:"2:1.16.4-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"xserver-xorg-core", reference:"2:1.16.4-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"xserver-xorg-core-dbg", reference:"2:1.16.4-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"xserver-xorg-core-udeb", reference:"2:1.16.4-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"xserver-xorg-dev", reference:"2:1.16.4-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"xvfb", reference:"2:1.16.4-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"xwayland", reference:"2:1.16.4-1+deb8u2")) flag++;
if (deb_check(release:"9.0", prefix:"xdmx", reference:"2:1.19.2-1+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"xdmx-tools", reference:"2:1.19.2-1+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"xnest", reference:"2:1.19.2-1+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"xorg-server-source", reference:"2:1.19.2-1+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"xserver-common", reference:"2:1.19.2-1+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"xserver-xephyr", reference:"2:1.19.2-1+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"xserver-xorg-core", reference:"2:1.19.2-1+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"xserver-xorg-core-udeb", reference:"2:1.19.2-1+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"xserver-xorg-dev", reference:"2:1.19.2-1+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"xserver-xorg-legacy", reference:"2:1.19.2-1+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"xvfb", reference:"2:1.19.2-1+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"xwayland", reference:"2:1.19.2-1+deb9u2")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
