#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-3972. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(103198);
  script_version("3.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2017-1000250");
  script_xref(name:"DSA", value:"3972");

  script_name(english:"Debian DSA-3972-1 : bluez - security update (BlueBorne)");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An information disclosure vulnerability was discovered in the Service
Discovery Protocol (SDP) in bluetoothd, allowing a proximate attacker
to obtain sensitive information from bluetoothd process memory,
including Bluetooth encryption keys."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=875633"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/jessie/bluez"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/stretch/bluez"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.debian.org/security/2017/dsa-3972"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the bluez packages.

For the oldstable distribution (jessie), this problem has been fixed
in version 5.23-2+deb8u1.

For the stable distribution (stretch), this problem has been fixed in
version 5.43-2+deb9u1."
  );
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:bluez");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:8.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:9.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/09/13");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/09/14");
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
if (deb_check(release:"8.0", prefix:"bluetooth", reference:"5.23-2+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"bluez", reference:"5.23-2+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"bluez-cups", reference:"5.23-2+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"bluez-dbg", reference:"5.23-2+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"bluez-hcidump", reference:"5.23-2+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"bluez-obexd", reference:"5.23-2+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"bluez-test-scripts", reference:"5.23-2+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libbluetooth-dev", reference:"5.23-2+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libbluetooth3", reference:"5.23-2+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libbluetooth3-dbg", reference:"5.23-2+deb8u1")) flag++;
if (deb_check(release:"9.0", prefix:"bluetooth", reference:"5.43-2+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"bluez", reference:"5.43-2+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"bluez-cups", reference:"5.43-2+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"bluez-dbg", reference:"5.43-2+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"bluez-hcidump", reference:"5.43-2+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"bluez-obexd", reference:"5.43-2+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"bluez-test-scripts", reference:"5.43-2+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"bluez-test-tools", reference:"5.43-2+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libbluetooth-dev", reference:"5.43-2+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libbluetooth3", reference:"5.43-2+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libbluetooth3-dbg", reference:"5.43-2+deb9u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_note(port:0, extra:deb_report_get());
  else security_note(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
