#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-4272. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(111707);
  script_version("1.6");
  script_cvs_date("Date: 2019/07/15 14:20:30");

  script_cve_id("CVE-2018-5391");
  script_xref(name:"DSA", value:"4272");

  script_name(english:"Debian DSA-4272-1 : linux - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"- CVE-2018-5391 (FragmentSmack)
    Juha-Matti Tilli discovered a flaw in the way the Linux
    kernel handled reassembly of fragmented IPv4 and IPv6
    packets. A remote attacker can take advantage of this
    flaw to trigger time and calculation expensive fragment
    reassembly algorithms by sending specially crafted
    packets, leading to remote denial of service.

  This is mitigated by reducing the default limits on memory usage for
  incomplete fragmented packets. The same mitigation can be achieved
  without the need to reboot, by setting the sysctls :

    net.ipv4.ipfrag_low_thresh = 196608 net.ipv6.ip6frag_low_thresh =
    196608 net.ipv4.ipfrag_high_thresh = 262144
    net.ipv6.ip6frag_high_thresh = 262144

  The default values may still be increased by local configuration if
  necessary."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2018-5391"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/source-package/linux"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/stretch/linux"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.debian.org/security/2018/dsa-4272"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the linux packages.

For the stable distribution (stretch), this problem has been fixed in
version 4.9.110-3+deb9u2."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:9.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/09/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/08/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/08/15");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2018-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (deb_check(release:"9.0", prefix:"hyperv-daemons", reference:"4.9.110-3+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"libcpupower-dev", reference:"4.9.110-3+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"libcpupower1", reference:"4.9.110-3+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"libusbip-dev", reference:"4.9.110-3+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"linux-compiler-gcc-6-arm", reference:"4.9.110-3+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"linux-compiler-gcc-6-s390", reference:"4.9.110-3+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"linux-compiler-gcc-6-x86", reference:"4.9.110-3+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"linux-cpupower", reference:"4.9.110-3+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"linux-doc-4.9", reference:"4.9.110-3+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"linux-headers-4.9.0-9-4kc-malta", reference:"4.9.110-3+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"linux-headers-4.9.0-9-5kc-malta", reference:"4.9.110-3+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"linux-headers-4.9.0-9-686", reference:"4.9.110-3+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"linux-headers-4.9.0-9-686-pae", reference:"4.9.110-3+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"linux-headers-4.9.0-9-all", reference:"4.9.110-3+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"linux-headers-4.9.0-9-all-amd64", reference:"4.9.110-3+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"linux-headers-4.9.0-9-all-arm64", reference:"4.9.110-3+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"linux-headers-4.9.0-9-all-armel", reference:"4.9.110-3+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"linux-headers-4.9.0-9-all-armhf", reference:"4.9.110-3+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"linux-headers-4.9.0-9-all-i386", reference:"4.9.110-3+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"linux-headers-4.9.0-9-all-mips", reference:"4.9.110-3+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"linux-headers-4.9.0-9-all-mips64el", reference:"4.9.110-3+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"linux-headers-4.9.0-9-all-mipsel", reference:"4.9.110-3+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"linux-headers-4.9.0-9-all-ppc64el", reference:"4.9.110-3+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"linux-headers-4.9.0-9-all-s390x", reference:"4.9.110-3+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"linux-headers-4.9.0-9-amd64", reference:"4.9.110-3+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"linux-headers-4.9.0-9-arm64", reference:"4.9.110-3+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"linux-headers-4.9.0-9-armmp", reference:"4.9.110-3+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"linux-headers-4.9.0-9-armmp-lpae", reference:"4.9.110-3+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"linux-headers-4.9.0-9-common", reference:"4.9.110-3+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"linux-headers-4.9.0-9-common-rt", reference:"4.9.110-3+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"linux-headers-4.9.0-9-loongson-3", reference:"4.9.110-3+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"linux-headers-4.9.0-9-marvell", reference:"4.9.110-3+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"linux-headers-4.9.0-9-octeon", reference:"4.9.110-3+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"linux-headers-4.9.0-9-powerpc64le", reference:"4.9.110-3+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"linux-headers-4.9.0-9-rt-686-pae", reference:"4.9.110-3+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"linux-headers-4.9.0-9-rt-amd64", reference:"4.9.110-3+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"linux-headers-4.9.0-9-s390x", reference:"4.9.110-3+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"linux-image-4.9.0-9-4kc-malta", reference:"4.9.110-3+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"linux-image-4.9.0-9-4kc-malta-dbg", reference:"4.9.110-3+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"linux-image-4.9.0-9-5kc-malta", reference:"4.9.110-3+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"linux-image-4.9.0-9-5kc-malta-dbg", reference:"4.9.110-3+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"linux-image-4.9.0-9-686", reference:"4.9.110-3+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"linux-image-4.9.0-9-686-dbg", reference:"4.9.110-3+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"linux-image-4.9.0-9-686-pae", reference:"4.9.110-3+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"linux-image-4.9.0-9-686-pae-dbg", reference:"4.9.110-3+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"linux-image-4.9.0-9-amd64", reference:"4.9.110-3+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"linux-image-4.9.0-9-amd64-dbg", reference:"4.9.110-3+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"linux-image-4.9.0-9-arm64", reference:"4.9.110-3+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"linux-image-4.9.0-9-arm64-dbg", reference:"4.9.110-3+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"linux-image-4.9.0-9-armmp", reference:"4.9.110-3+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"linux-image-4.9.0-9-armmp-dbg", reference:"4.9.110-3+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"linux-image-4.9.0-9-armmp-lpae", reference:"4.9.110-3+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"linux-image-4.9.0-9-armmp-lpae-dbg", reference:"4.9.110-3+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"linux-image-4.9.0-9-loongson-3", reference:"4.9.110-3+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"linux-image-4.9.0-9-loongson-3-dbg", reference:"4.9.110-3+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"linux-image-4.9.0-9-marvell", reference:"4.9.110-3+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"linux-image-4.9.0-9-marvell-dbg", reference:"4.9.110-3+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"linux-image-4.9.0-9-octeon", reference:"4.9.110-3+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"linux-image-4.9.0-9-octeon-dbg", reference:"4.9.110-3+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"linux-image-4.9.0-9-powerpc64le", reference:"4.9.110-3+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"linux-image-4.9.0-9-powerpc64le-dbg", reference:"4.9.110-3+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"linux-image-4.9.0-9-rt-686-pae", reference:"4.9.110-3+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"linux-image-4.9.0-9-rt-686-pae-dbg", reference:"4.9.110-3+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"linux-image-4.9.0-9-rt-amd64", reference:"4.9.110-3+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"linux-image-4.9.0-9-rt-amd64-dbg", reference:"4.9.110-3+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"linux-image-4.9.0-9-s390x", reference:"4.9.110-3+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"linux-image-4.9.0-9-s390x-dbg", reference:"4.9.110-3+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"linux-kbuild-4.9", reference:"4.9.110-3+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"linux-libc-dev", reference:"4.9.110-3+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"linux-manual-4.9", reference:"4.9.110-3+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"linux-perf-4.9", reference:"4.9.110-3+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"linux-source-4.9", reference:"4.9.110-3+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"linux-support-4.9.0-9", reference:"4.9.110-3+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"usbip", reference:"4.9.110-3+deb9u2")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
