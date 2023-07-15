#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-4313. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(118023);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/02/10");

  script_cve_id("CVE-2018-15471", "CVE-2018-18021");
  script_xref(name:"DSA", value:"4313");

  script_name(english:"Debian DSA-4313-1 : linux - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"Several vulnerabilities have been discovered in the Linux kernel that
may lead to a privilege escalation, denial of service or information
leaks.

  - CVE-2018-15471 (XSA-270)
    Felix Wilhelm of Google Project Zero discovered a flaw
    in the hash handling of the xen-netback Linux kernel
    module. A malicious or buggy frontend may cause the
    (usually privileged) backend to make out of bounds
    memory accesses, potentially resulting in privilege
    escalation, denial of service, or information leaks.

  - CVE-2018-18021
    It was discovered that the KVM subsystem on the arm64
    platform does not properly handle the KVM_SET_ON_REG
    ioctl. An attacker who can create KVM based virtual
    machines can take advantage of this flaw for denial of
    service (hypervisor panic) or privilege escalation
    (arbitrarily redirect the hypervisor flow of control
    with full register control)."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2018-15471"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2018-18021"
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
    value:"https://www.debian.org/security/2018/dsa-4313"
  );
  script_set_attribute(
    attribute:"solution",
    value:
"Upgrade the linux packages.

For the stable distribution (stretch), these problems have been fixed
in version 4.9.110-3+deb9u6."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-15471");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:9.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/08/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/10/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/10/10");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2018-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (deb_check(release:"9.0", prefix:"hyperv-daemons", reference:"4.9.110-3+deb9u6")) flag++;
if (deb_check(release:"9.0", prefix:"libcpupower-dev", reference:"4.9.110-3+deb9u6")) flag++;
if (deb_check(release:"9.0", prefix:"libcpupower1", reference:"4.9.110-3+deb9u6")) flag++;
if (deb_check(release:"9.0", prefix:"libusbip-dev", reference:"4.9.110-3+deb9u6")) flag++;
if (deb_check(release:"9.0", prefix:"linux-compiler-gcc-6-arm", reference:"4.9.110-3+deb9u6")) flag++;
if (deb_check(release:"9.0", prefix:"linux-compiler-gcc-6-s390", reference:"4.9.110-3+deb9u6")) flag++;
if (deb_check(release:"9.0", prefix:"linux-compiler-gcc-6-x86", reference:"4.9.110-3+deb9u6")) flag++;
if (deb_check(release:"9.0", prefix:"linux-cpupower", reference:"4.9.110-3+deb9u6")) flag++;
if (deb_check(release:"9.0", prefix:"linux-doc-4.9", reference:"4.9.110-3+deb9u6")) flag++;
if (deb_check(release:"9.0", prefix:"linux-headers-4.9.0-9-4kc-malta", reference:"4.9.110-3+deb9u6")) flag++;
if (deb_check(release:"9.0", prefix:"linux-headers-4.9.0-9-5kc-malta", reference:"4.9.110-3+deb9u6")) flag++;
if (deb_check(release:"9.0", prefix:"linux-headers-4.9.0-9-686", reference:"4.9.110-3+deb9u6")) flag++;
if (deb_check(release:"9.0", prefix:"linux-headers-4.9.0-9-686-pae", reference:"4.9.110-3+deb9u6")) flag++;
if (deb_check(release:"9.0", prefix:"linux-headers-4.9.0-9-all", reference:"4.9.110-3+deb9u6")) flag++;
if (deb_check(release:"9.0", prefix:"linux-headers-4.9.0-9-all-amd64", reference:"4.9.110-3+deb9u6")) flag++;
if (deb_check(release:"9.0", prefix:"linux-headers-4.9.0-9-all-arm64", reference:"4.9.110-3+deb9u6")) flag++;
if (deb_check(release:"9.0", prefix:"linux-headers-4.9.0-9-all-armel", reference:"4.9.110-3+deb9u6")) flag++;
if (deb_check(release:"9.0", prefix:"linux-headers-4.9.0-9-all-armhf", reference:"4.9.110-3+deb9u6")) flag++;
if (deb_check(release:"9.0", prefix:"linux-headers-4.9.0-9-all-i386", reference:"4.9.110-3+deb9u6")) flag++;
if (deb_check(release:"9.0", prefix:"linux-headers-4.9.0-9-all-mips", reference:"4.9.110-3+deb9u6")) flag++;
if (deb_check(release:"9.0", prefix:"linux-headers-4.9.0-9-all-mips64el", reference:"4.9.110-3+deb9u6")) flag++;
if (deb_check(release:"9.0", prefix:"linux-headers-4.9.0-9-all-mipsel", reference:"4.9.110-3+deb9u6")) flag++;
if (deb_check(release:"9.0", prefix:"linux-headers-4.9.0-9-all-ppc64el", reference:"4.9.110-3+deb9u6")) flag++;
if (deb_check(release:"9.0", prefix:"linux-headers-4.9.0-9-all-s390x", reference:"4.9.110-3+deb9u6")) flag++;
if (deb_check(release:"9.0", prefix:"linux-headers-4.9.0-9-amd64", reference:"4.9.110-3+deb9u6")) flag++;
if (deb_check(release:"9.0", prefix:"linux-headers-4.9.0-9-arm64", reference:"4.9.110-3+deb9u6")) flag++;
if (deb_check(release:"9.0", prefix:"linux-headers-4.9.0-9-armmp", reference:"4.9.110-3+deb9u6")) flag++;
if (deb_check(release:"9.0", prefix:"linux-headers-4.9.0-9-armmp-lpae", reference:"4.9.110-3+deb9u6")) flag++;
if (deb_check(release:"9.0", prefix:"linux-headers-4.9.0-9-common", reference:"4.9.110-3+deb9u6")) flag++;
if (deb_check(release:"9.0", prefix:"linux-headers-4.9.0-9-common-rt", reference:"4.9.110-3+deb9u6")) flag++;
if (deb_check(release:"9.0", prefix:"linux-headers-4.9.0-9-loongson-3", reference:"4.9.110-3+deb9u6")) flag++;
if (deb_check(release:"9.0", prefix:"linux-headers-4.9.0-9-marvell", reference:"4.9.110-3+deb9u6")) flag++;
if (deb_check(release:"9.0", prefix:"linux-headers-4.9.0-9-octeon", reference:"4.9.110-3+deb9u6")) flag++;
if (deb_check(release:"9.0", prefix:"linux-headers-4.9.0-9-powerpc64le", reference:"4.9.110-3+deb9u6")) flag++;
if (deb_check(release:"9.0", prefix:"linux-headers-4.9.0-9-rt-686-pae", reference:"4.9.110-3+deb9u6")) flag++;
if (deb_check(release:"9.0", prefix:"linux-headers-4.9.0-9-rt-amd64", reference:"4.9.110-3+deb9u6")) flag++;
if (deb_check(release:"9.0", prefix:"linux-headers-4.9.0-9-s390x", reference:"4.9.110-3+deb9u6")) flag++;
if (deb_check(release:"9.0", prefix:"linux-image-4.9.0-9-4kc-malta", reference:"4.9.110-3+deb9u6")) flag++;
if (deb_check(release:"9.0", prefix:"linux-image-4.9.0-9-4kc-malta-dbg", reference:"4.9.110-3+deb9u6")) flag++;
if (deb_check(release:"9.0", prefix:"linux-image-4.9.0-9-5kc-malta", reference:"4.9.110-3+deb9u6")) flag++;
if (deb_check(release:"9.0", prefix:"linux-image-4.9.0-9-5kc-malta-dbg", reference:"4.9.110-3+deb9u6")) flag++;
if (deb_check(release:"9.0", prefix:"linux-image-4.9.0-9-686", reference:"4.9.110-3+deb9u6")) flag++;
if (deb_check(release:"9.0", prefix:"linux-image-4.9.0-9-686-dbg", reference:"4.9.110-3+deb9u6")) flag++;
if (deb_check(release:"9.0", prefix:"linux-image-4.9.0-9-686-pae", reference:"4.9.110-3+deb9u6")) flag++;
if (deb_check(release:"9.0", prefix:"linux-image-4.9.0-9-686-pae-dbg", reference:"4.9.110-3+deb9u6")) flag++;
if (deb_check(release:"9.0", prefix:"linux-image-4.9.0-9-amd64", reference:"4.9.110-3+deb9u6")) flag++;
if (deb_check(release:"9.0", prefix:"linux-image-4.9.0-9-amd64-dbg", reference:"4.9.110-3+deb9u6")) flag++;
if (deb_check(release:"9.0", prefix:"linux-image-4.9.0-9-arm64", reference:"4.9.110-3+deb9u6")) flag++;
if (deb_check(release:"9.0", prefix:"linux-image-4.9.0-9-arm64-dbg", reference:"4.9.110-3+deb9u6")) flag++;
if (deb_check(release:"9.0", prefix:"linux-image-4.9.0-9-armmp", reference:"4.9.110-3+deb9u6")) flag++;
if (deb_check(release:"9.0", prefix:"linux-image-4.9.0-9-armmp-dbg", reference:"4.9.110-3+deb9u6")) flag++;
if (deb_check(release:"9.0", prefix:"linux-image-4.9.0-9-armmp-lpae", reference:"4.9.110-3+deb9u6")) flag++;
if (deb_check(release:"9.0", prefix:"linux-image-4.9.0-9-armmp-lpae-dbg", reference:"4.9.110-3+deb9u6")) flag++;
if (deb_check(release:"9.0", prefix:"linux-image-4.9.0-9-loongson-3", reference:"4.9.110-3+deb9u6")) flag++;
if (deb_check(release:"9.0", prefix:"linux-image-4.9.0-9-loongson-3-dbg", reference:"4.9.110-3+deb9u6")) flag++;
if (deb_check(release:"9.0", prefix:"linux-image-4.9.0-9-marvell", reference:"4.9.110-3+deb9u6")) flag++;
if (deb_check(release:"9.0", prefix:"linux-image-4.9.0-9-marvell-dbg", reference:"4.9.110-3+deb9u6")) flag++;
if (deb_check(release:"9.0", prefix:"linux-image-4.9.0-9-octeon", reference:"4.9.110-3+deb9u6")) flag++;
if (deb_check(release:"9.0", prefix:"linux-image-4.9.0-9-octeon-dbg", reference:"4.9.110-3+deb9u6")) flag++;
if (deb_check(release:"9.0", prefix:"linux-image-4.9.0-9-powerpc64le", reference:"4.9.110-3+deb9u6")) flag++;
if (deb_check(release:"9.0", prefix:"linux-image-4.9.0-9-powerpc64le-dbg", reference:"4.9.110-3+deb9u6")) flag++;
if (deb_check(release:"9.0", prefix:"linux-image-4.9.0-9-rt-686-pae", reference:"4.9.110-3+deb9u6")) flag++;
if (deb_check(release:"9.0", prefix:"linux-image-4.9.0-9-rt-686-pae-dbg", reference:"4.9.110-3+deb9u6")) flag++;
if (deb_check(release:"9.0", prefix:"linux-image-4.9.0-9-rt-amd64", reference:"4.9.110-3+deb9u6")) flag++;
if (deb_check(release:"9.0", prefix:"linux-image-4.9.0-9-rt-amd64-dbg", reference:"4.9.110-3+deb9u6")) flag++;
if (deb_check(release:"9.0", prefix:"linux-image-4.9.0-9-s390x", reference:"4.9.110-3+deb9u6")) flag++;
if (deb_check(release:"9.0", prefix:"linux-image-4.9.0-9-s390x-dbg", reference:"4.9.110-3+deb9u6")) flag++;
if (deb_check(release:"9.0", prefix:"linux-kbuild-4.9", reference:"4.9.110-3+deb9u6")) flag++;
if (deb_check(release:"9.0", prefix:"linux-libc-dev", reference:"4.9.110-3+deb9u6")) flag++;
if (deb_check(release:"9.0", prefix:"linux-manual-4.9", reference:"4.9.110-3+deb9u6")) flag++;
if (deb_check(release:"9.0", prefix:"linux-perf-4.9", reference:"4.9.110-3+deb9u6")) flag++;
if (deb_check(release:"9.0", prefix:"linux-source-4.9", reference:"4.9.110-3+deb9u6")) flag++;
if (deb_check(release:"9.0", prefix:"linux-support-4.9.0-9", reference:"4.9.110-3+deb9u6")) flag++;
if (deb_check(release:"9.0", prefix:"usbip", reference:"4.9.110-3+deb9u6")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
