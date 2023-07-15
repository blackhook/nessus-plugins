#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-4213. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(110208);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/09/11");

  script_cve_id("CVE-2017-15038", "CVE-2017-15119", "CVE-2017-15124", "CVE-2017-15268", "CVE-2017-15289", "CVE-2017-16845", "CVE-2017-17381", "CVE-2017-18043", "CVE-2017-5715", "CVE-2018-5683", "CVE-2018-7550");
  script_xref(name:"DSA", value:"4213");

  script_name(english:"Debian DSA-4213-1 : qemu - security update (Spectre)");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"Several vulnerabilities were discovered in qemu, a fast processor
emulator.

  - CVE-2017-15038
    Tuomas Tynkkynen discovered an information leak in 9pfs.

  - CVE-2017-15119
    Eric Blake discovered that the NBD server insufficiently
    restricts large option requests, resulting in denial of
    service.

  - CVE-2017-15124
    Daniel Berrange discovered that the integrated VNC
    server insufficiently restricted memory allocation,
    which could result in denial of service.

  - CVE-2017-15268
    A memory leak in websockets support may result in denial
    of service.

  - CVE-2017-15289
    Guoxiang Niu discovered an OOB write in the emulated
    Cirrus graphics adaptor which could result in denial of
    service.

  - CVE-2017-16845
    Cyrille Chatras discovered an information leak in PS/2
    mouse and keyboard emulation which could be exploited
    during instance migration.

  - CVE-2017-17381
    Dengzhan Heyuandong Bijunhua and Liweichao discovered
    that an implementation error in the virtio vring
    implementation could result in denial of service.

  - CVE-2017-18043
    Eric Blake discovered an integer overflow in an
    internally used macro which could result in denial of
    service.

  - CVE-2018-5683
    Jiang Xin and Lin ZheCheng discovered an OOB memory
    access in the emulated VGA adaptor which could result in
    denial of service.

  - CVE-2018-7550
    Cyrille Chatras discovered that an OOB memory write when
    using multiboot could result in the execution of
    arbitrary code.

This update also backports a number of mitigations against the Spectre
v2 vulnerability affecting modern CPUs (CVE-2017-5715 ). For
additional information please refer to
https://www.qemu.org/2018/01/04/spectre/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=877890"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=880832"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=880836"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=882136"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=883399"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=883625"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=884806"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=886532"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2017-15038"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2017-15119"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2017-15124"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2017-15268"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2017-15289"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2017-16845"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2017-17381"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2017-18043"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2018-5683"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2018-7550"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2017-5715"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.qemu.org/2018/01/04/spectre/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/source-package/qemu"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/stretch/qemu"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.debian.org/security/2018/dsa-4213"
  );
  script_set_attribute(
    attribute:"solution",
    value:
"Upgrade the qemu packages.

For the stable distribution (stretch), these problems have been fixed
in version 1:2.8+dfsg-6+deb9u4."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:qemu");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:9.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/10/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/05/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/05/30");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2018-2020 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (deb_check(release:"9.0", prefix:"qemu", reference:"1:2.8+dfsg-6+deb9u4")) flag++;
if (deb_check(release:"9.0", prefix:"qemu-block-extra", reference:"1:2.8+dfsg-6+deb9u4")) flag++;
if (deb_check(release:"9.0", prefix:"qemu-guest-agent", reference:"1:2.8+dfsg-6+deb9u4")) flag++;
if (deb_check(release:"9.0", prefix:"qemu-kvm", reference:"1:2.8+dfsg-6+deb9u4")) flag++;
if (deb_check(release:"9.0", prefix:"qemu-system", reference:"1:2.8+dfsg-6+deb9u4")) flag++;
if (deb_check(release:"9.0", prefix:"qemu-system-arm", reference:"1:2.8+dfsg-6+deb9u4")) flag++;
if (deb_check(release:"9.0", prefix:"qemu-system-common", reference:"1:2.8+dfsg-6+deb9u4")) flag++;
if (deb_check(release:"9.0", prefix:"qemu-system-mips", reference:"1:2.8+dfsg-6+deb9u4")) flag++;
if (deb_check(release:"9.0", prefix:"qemu-system-misc", reference:"1:2.8+dfsg-6+deb9u4")) flag++;
if (deb_check(release:"9.0", prefix:"qemu-system-ppc", reference:"1:2.8+dfsg-6+deb9u4")) flag++;
if (deb_check(release:"9.0", prefix:"qemu-system-sparc", reference:"1:2.8+dfsg-6+deb9u4")) flag++;
if (deb_check(release:"9.0", prefix:"qemu-system-x86", reference:"1:2.8+dfsg-6+deb9u4")) flag++;
if (deb_check(release:"9.0", prefix:"qemu-user", reference:"1:2.8+dfsg-6+deb9u4")) flag++;
if (deb_check(release:"9.0", prefix:"qemu-user-binfmt", reference:"1:2.8+dfsg-6+deb9u4")) flag++;
if (deb_check(release:"9.0", prefix:"qemu-user-static", reference:"1:2.8+dfsg-6+deb9u4")) flag++;
if (deb_check(release:"9.0", prefix:"qemu-utils", reference:"1:2.8+dfsg-6+deb9u4")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
