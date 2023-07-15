#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-4003. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(103994);
  script_version("3.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2017-1000256");
  script_xref(name:"DSA", value:"4003");

  script_name(english:"Debian DSA-4003-1 : libvirt - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Daniel P. Berrange reported that Libvirt, a virtualisation abstraction
library, does not properly handle the default_tls_x509_verify (and
related) parameters in qemu.conf when setting up TLS clients and
servers in QEMU, resulting in TLS clients for character devices and
disk devices having verification turned off and ignoring any errors
while validating the server certificate.

More informations in https://security.libvirt.org/2017/0002.html ."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=878799"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.libvirt.org/2017/0002.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/stretch/libvirt"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.debian.org/security/2017/dsa-4003"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the libvirt packages.

For the stable distribution (stretch), this problem has been fixed in
version 3.0.0-4+deb9u1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libvirt");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:9.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/10/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/10/20");
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
if (deb_check(release:"9.0", prefix:"libnss-libvirt", reference:"3.0.0-4+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libvirt-clients", reference:"3.0.0-4+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libvirt-daemon", reference:"3.0.0-4+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libvirt-daemon-system", reference:"3.0.0-4+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libvirt-dev", reference:"3.0.0-4+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libvirt-doc", reference:"3.0.0-4+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libvirt-sanlock", reference:"3.0.0-4+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libvirt0", reference:"3.0.0-4+deb9u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
