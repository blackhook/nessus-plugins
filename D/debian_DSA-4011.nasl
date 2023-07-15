#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-4011. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(104259);
  script_version("3.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2017-16227");
  script_xref(name:"DSA", value:"4011");

  script_name(english:"Debian DSA-4011-1 : quagga - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"It was discovered that the bgpd daemon in the Quagga routing suite
does not properly calculate the length of multi-segment AS_PATH UPDATE
messages, causing bgpd to drop a session and potentially resulting in
loss of network connectivity."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=879474"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/jessie/quagga"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/stretch/quagga"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.debian.org/security/2017/dsa-4011"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the quagga packages.

For the oldstable distribution (jessie), this problem has been fixed
in version 0.99.23.1-1+deb8u4.

For the stable distribution (stretch), this problem has been fixed in
version 1.1.1-3+deb9u1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:quagga");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:8.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:9.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/10/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/10/31");
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
if (deb_check(release:"8.0", prefix:"quagga", reference:"0.99.23.1-1+deb8u4")) flag++;
if (deb_check(release:"8.0", prefix:"quagga-dbg", reference:"0.99.23.1-1+deb8u4")) flag++;
if (deb_check(release:"8.0", prefix:"quagga-doc", reference:"0.99.23.1-1+deb8u4")) flag++;
if (deb_check(release:"9.0", prefix:"quagga", reference:"1.1.1-3+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"quagga-bgpd", reference:"1.1.1-3+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"quagga-core", reference:"1.1.1-3+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"quagga-doc", reference:"1.1.1-3+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"quagga-isisd", reference:"1.1.1-3+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"quagga-ospf6d", reference:"1.1.1-3+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"quagga-ospfd", reference:"1.1.1-3+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"quagga-pimd", reference:"1.1.1-3+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"quagga-ripd", reference:"1.1.1-3+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"quagga-ripngd", reference:"1.1.1-3+deb9u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
