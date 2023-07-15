#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-3950. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(102630);
  script_version("3.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2017-6886", "CVE-2017-6887");
  script_xref(name:"DSA", value:"3950");

  script_name(english:"Debian DSA-3950-1 : libraw - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Hossein Lotfi and Jakub Jirasek from Secunia Research have discovered
multiple vulnerabilities in LibRaw, a library for reading RAW images.
An attacker could cause a memory corruption leading to a DoS (Denial
of Service) with craft KDC or TIFF file."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=864183"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/jessie/libraw"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/stretch/libraw"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.debian.org/security/2017/dsa-3950"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the libraw packages.

For the oldstable distribution (jessie), these problems have been
fixed in version 0.16.0-9+deb8u3.

For the stable distribution (stretch), these problems have been fixed
in version 0.17.2-6+deb9u1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libraw");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:8.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:9.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/08/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/08/22");
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
if (deb_check(release:"8.0", prefix:"libraw-bin", reference:"0.16.0-9+deb8u3")) flag++;
if (deb_check(release:"8.0", prefix:"libraw-dev", reference:"0.16.0-9+deb8u3")) flag++;
if (deb_check(release:"8.0", prefix:"libraw-doc", reference:"0.16.0-9+deb8u3")) flag++;
if (deb_check(release:"8.0", prefix:"libraw10", reference:"0.16.0-9+deb8u3")) flag++;
if (deb_check(release:"9.0", prefix:"libraw-bin", reference:"0.17.2-6+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libraw-dev", reference:"0.17.2-6+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libraw-doc", reference:"0.17.2-6+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libraw15", reference:"0.17.2-6+deb9u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
