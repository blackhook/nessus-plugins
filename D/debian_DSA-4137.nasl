#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-4137. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(108346);
  script_version("1.5");
  script_cvs_date("Date: 2018/11/13 12:30:46");

  script_cve_id("CVE-2018-1064", "CVE-2018-5748", "CVE-2018-6764");
  script_xref(name:"DSA", value:"4137");

  script_name(english:"Debian DSA-4137-1 : libvirt - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several vulnerabilities were discovered in Libvirt, a virtualisation
abstraction library :

  - CVE-2018-1064
    Daniel Berrange discovered that the QEMU guest agent
    performed insufficient validation of incoming data,
    which allows a privileged user in the guest to exhaust
    resources on the virtualisation host, resulting in
    denial of service.

  - CVE-2018-5748
    Daniel Berrange and Peter Krempa discovered that the
    QEMU monitor was susceptible to denial of service by
    memory exhaustion. This was already fixed in Debian
    stretch and only affects Debian jessie.

  - CVE-2018-6764
    Pedro Sampaio discovered that LXC containers detected
    the hostname insecurely. This only affects Debian
    stretch."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2018-1064"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2018-5748"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2018-6764"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/source-package/libvirt"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/jessie/libvirt"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/stretch/libvirt"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.debian.org/security/2018/dsa-4137"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the libvirt packages.

For the oldstable distribution (jessie), these problems have been
fixed in version 1.2.9-9+deb8u5.

For the stable distribution (stretch), these problems have been fixed
in version 3.0.0-4+deb9u3."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libvirt");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:8.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:9.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2018/03/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/03/15");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2018 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (deb_check(release:"8.0", prefix:"libvirt-bin", reference:"1.2.9-9+deb8u5")) flag++;
if (deb_check(release:"8.0", prefix:"libvirt-clients", reference:"1.2.9-9+deb8u5")) flag++;
if (deb_check(release:"8.0", prefix:"libvirt-daemon", reference:"1.2.9-9+deb8u5")) flag++;
if (deb_check(release:"8.0", prefix:"libvirt-daemon-system", reference:"1.2.9-9+deb8u5")) flag++;
if (deb_check(release:"8.0", prefix:"libvirt-dev", reference:"1.2.9-9+deb8u5")) flag++;
if (deb_check(release:"8.0", prefix:"libvirt-doc", reference:"1.2.9-9+deb8u5")) flag++;
if (deb_check(release:"8.0", prefix:"libvirt-sanlock", reference:"1.2.9-9+deb8u5")) flag++;
if (deb_check(release:"8.0", prefix:"libvirt0", reference:"1.2.9-9+deb8u5")) flag++;
if (deb_check(release:"8.0", prefix:"libvirt0-dbg", reference:"1.2.9-9+deb8u5")) flag++;
if (deb_check(release:"9.0", prefix:"libnss-libvirt", reference:"3.0.0-4+deb9u3")) flag++;
if (deb_check(release:"9.0", prefix:"libvirt-clients", reference:"3.0.0-4+deb9u3")) flag++;
if (deb_check(release:"9.0", prefix:"libvirt-daemon", reference:"3.0.0-4+deb9u3")) flag++;
if (deb_check(release:"9.0", prefix:"libvirt-daemon-system", reference:"3.0.0-4+deb9u3")) flag++;
if (deb_check(release:"9.0", prefix:"libvirt-dev", reference:"3.0.0-4+deb9u3")) flag++;
if (deb_check(release:"9.0", prefix:"libvirt-doc", reference:"3.0.0-4+deb9u3")) flag++;
if (deb_check(release:"9.0", prefix:"libvirt-sanlock", reference:"3.0.0-4+deb9u3")) flag++;
if (deb_check(release:"9.0", prefix:"libvirt0", reference:"3.0.0-4+deb9u3")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
