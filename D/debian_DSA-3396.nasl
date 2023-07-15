#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-3396. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(86832);
  script_version("2.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/11");

  script_cve_id("CVE-2015-5307", "CVE-2015-7833", "CVE-2015-7872", "CVE-2015-7990");
  script_xref(name:"DSA", value:"3396");

  script_name(english:"Debian DSA-3396-1 : linux - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several vulnerabilities have been discovered in the Linux kernel that
may lead to a denial of service.

  - CVE-2015-5307
    Ben Serebrin from Google discovered a guest to host
    denial of service flaw affecting the KVM hypervisor. A
    malicious guest can trigger an infinite stream of
    'alignment check' (#AC) exceptions causing the processor
    microcode to enter an infinite loop where the core never
    receives another interrupt. This leads to a panic of the
    host kernel.

  - CVE-2015-7833
    Sergej Schumilo, Hendrik Schwartke and Ralf Spenneberg
    discovered a flaw in the processing of certain USB
    device descriptors in the usbvision driver. An attacker
    with physical access to the system can use this flaw to
    crash the system.

  - CVE-2015-7872
    Dmitry Vyukov discovered a vulnerability in the keyrings
    garbage collector allowing a local user to trigger a
    kernel panic.

  - CVE-2015-7990
    It was discovered that the fix for CVE-2015-6937 was
    incomplete. A race condition when sending a message on
    unbound socket can still cause a NULL pointer
    dereference. A remote attacker might be able to cause a
    denial of service (crash) by sending a crafted packet."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2015-5307"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2015-7833"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2015-7872"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2015-7990"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2015-6937"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/jessie/linux"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.debian.org/security/2015/dsa-3396"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the linux packages.

For the oldstable distribution (wheezy), these problems have been
fixed in version 3.2.68-1+deb7u6.

For the stable distribution (jessie), these problems have been fixed
in version 3.16.7-ckt11-1+deb8u6."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:P/I:P/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:H/PR:L/UI:N/S:U/C:L/I:L/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:7.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:8.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/10/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/11/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/11/11");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (deb_check(release:"7.0", prefix:"linux", reference:"3.2.68-1+deb7u6")) flag++;
if (deb_check(release:"8.0", prefix:"linux-compiler-gcc-4.8-arm", reference:"3.16.7-ckt11-1+deb8u6")) flag++;
if (deb_check(release:"8.0", prefix:"linux-compiler-gcc-4.8-x86", reference:"3.16.7-ckt11-1+deb8u6")) flag++;
if (deb_check(release:"8.0", prefix:"linux-compiler-gcc-4.9-x86", reference:"3.16.7-ckt11-1+deb8u6")) flag++;
if (deb_check(release:"8.0", prefix:"linux-doc-3.16", reference:"3.16.7-ckt11-1+deb8u6")) flag++;
if (deb_check(release:"8.0", prefix:"linux-headers-3.16.0-9-586", reference:"3.16.7-ckt11-1+deb8u6")) flag++;
if (deb_check(release:"8.0", prefix:"linux-headers-3.16.0-9-686-pae", reference:"3.16.7-ckt11-1+deb8u6")) flag++;
if (deb_check(release:"8.0", prefix:"linux-headers-3.16.0-9-all", reference:"3.16.7-ckt11-1+deb8u6")) flag++;
if (deb_check(release:"8.0", prefix:"linux-headers-3.16.0-9-all-amd64", reference:"3.16.7-ckt11-1+deb8u6")) flag++;
if (deb_check(release:"8.0", prefix:"linux-headers-3.16.0-9-all-armel", reference:"3.16.7-ckt11-1+deb8u6")) flag++;
if (deb_check(release:"8.0", prefix:"linux-headers-3.16.0-9-all-armhf", reference:"3.16.7-ckt11-1+deb8u6")) flag++;
if (deb_check(release:"8.0", prefix:"linux-headers-3.16.0-9-all-i386", reference:"3.16.7-ckt11-1+deb8u6")) flag++;
if (deb_check(release:"8.0", prefix:"linux-headers-3.16.0-9-amd64", reference:"3.16.7-ckt11-1+deb8u6")) flag++;
if (deb_check(release:"8.0", prefix:"linux-headers-3.16.0-9-armmp", reference:"3.16.7-ckt11-1+deb8u6")) flag++;
if (deb_check(release:"8.0", prefix:"linux-headers-3.16.0-9-armmp-lpae", reference:"3.16.7-ckt11-1+deb8u6")) flag++;
if (deb_check(release:"8.0", prefix:"linux-headers-3.16.0-9-common", reference:"3.16.7-ckt11-1+deb8u6")) flag++;
if (deb_check(release:"8.0", prefix:"linux-headers-3.16.0-9-ixp4xx", reference:"3.16.7-ckt11-1+deb8u6")) flag++;
if (deb_check(release:"8.0", prefix:"linux-headers-3.16.0-9-kirkwood", reference:"3.16.7-ckt11-1+deb8u6")) flag++;
if (deb_check(release:"8.0", prefix:"linux-headers-3.16.0-9-orion5x", reference:"3.16.7-ckt11-1+deb8u6")) flag++;
if (deb_check(release:"8.0", prefix:"linux-headers-3.16.0-9-versatile", reference:"3.16.7-ckt11-1+deb8u6")) flag++;
if (deb_check(release:"8.0", prefix:"linux-image-3.16.0-9-586", reference:"3.16.7-ckt11-1+deb8u6")) flag++;
if (deb_check(release:"8.0", prefix:"linux-image-3.16.0-9-686-pae", reference:"3.16.7-ckt11-1+deb8u6")) flag++;
if (deb_check(release:"8.0", prefix:"linux-image-3.16.0-9-686-pae-dbg", reference:"3.16.7-ckt11-1+deb8u6")) flag++;
if (deb_check(release:"8.0", prefix:"linux-image-3.16.0-9-amd64", reference:"3.16.7-ckt11-1+deb8u6")) flag++;
if (deb_check(release:"8.0", prefix:"linux-image-3.16.0-9-amd64-dbg", reference:"3.16.7-ckt11-1+deb8u6")) flag++;
if (deb_check(release:"8.0", prefix:"linux-image-3.16.0-9-armmp", reference:"3.16.7-ckt11-1+deb8u6")) flag++;
if (deb_check(release:"8.0", prefix:"linux-image-3.16.0-9-armmp-lpae", reference:"3.16.7-ckt11-1+deb8u6")) flag++;
if (deb_check(release:"8.0", prefix:"linux-image-3.16.0-9-ixp4xx", reference:"3.16.7-ckt11-1+deb8u6")) flag++;
if (deb_check(release:"8.0", prefix:"linux-image-3.16.0-9-kirkwood", reference:"3.16.7-ckt11-1+deb8u6")) flag++;
if (deb_check(release:"8.0", prefix:"linux-image-3.16.0-9-orion5x", reference:"3.16.7-ckt11-1+deb8u6")) flag++;
if (deb_check(release:"8.0", prefix:"linux-image-3.16.0-9-versatile", reference:"3.16.7-ckt11-1+deb8u6")) flag++;
if (deb_check(release:"8.0", prefix:"linux-libc-dev", reference:"3.16.7-ckt11-1+deb8u6")) flag++;
if (deb_check(release:"8.0", prefix:"linux-manual-3.16", reference:"3.16.7-ckt11-1+deb8u6")) flag++;
if (deb_check(release:"8.0", prefix:"linux-source-3.16", reference:"3.16.7-ckt11-1+deb8u6")) flag++;
if (deb_check(release:"8.0", prefix:"linux-support-3.16.0-9", reference:"3.16.7-ckt11-1+deb8u6")) flag++;
if (deb_check(release:"8.0", prefix:"xen-linux-system-3.16.0-9-amd64", reference:"3.16.7-ckt11-1+deb8u6")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
