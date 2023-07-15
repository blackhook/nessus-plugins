#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-3313. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(84965);
  script_version("2.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/11");

  script_cve_id("CVE-2015-3290", "CVE-2015-3291", "CVE-2015-4167", "CVE-2015-5157", "CVE-2015-5364", "CVE-2015-5366");
  script_bugtraq_id(74963, 75510, 76003, 76004, 76005);
  script_xref(name:"DSA", value:"3313");

  script_name(english:"Debian DSA-3313-1 : linux - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several vulnerabilities have been discovered in the Linux kernel that
may lead to a privilege escalation or denial of service.

  - CVE-2015-3290
    Andy Lutomirski discovered that the Linux kernel does
    not properly handle nested NMIs. A local, unprivileged
    user could use this flaw for privilege escalation.

  - CVE-2015-3291
    Andy Lutomirski discovered that under certain conditions
    a malicious userspace program can cause the kernel to
    skip NMIs leading to a denial of service.

  - CVE-2015-4167
    Carl Henrik Lunde discovered that the UDF implementation
    is missing a necessary length check. A local user that
    can mount devices could use this flaw to crash the
    system.

  - CVE-2015-5157
    Petr Matousek and Andy Lutomirski discovered that an NMI
    that interrupts userspace and encounters an IRET fault
    is incorrectly handled. A local, unprivileged user could
    use this flaw for denial of service or possibly for
    privilege escalation.

  - CVE-2015-5364
    It was discovered that the Linux kernel does not
    properly handle invalid UDP checksums. A remote attacker
    could exploit this flaw to cause a denial of service
    using a flood of UDP packets with invalid checksums.

  - CVE-2015-5366
    It was discovered that the Linux kernel does not
    properly handle invalid UDP checksums. A remote attacker
    can cause a denial of service against applications that
    use epoll by injecting a single packet with an invalid
    checksum."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2015-3290"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2015-3291"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2015-4167"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2015-5157"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2015-5364"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2015-5366"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/jessie/linux"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.debian.org/security/2015/dsa-3313"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the linux packages.

For the stable distribution (jessie), these problems have been fixed
in version 3.16.7-ckt11-1+deb8u2."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:8.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/08/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/07/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/07/24");
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
if (deb_check(release:"8.0", prefix:"linux-compiler-gcc-4.8-arm", reference:"3.16.7-ckt11-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"linux-compiler-gcc-4.8-x86", reference:"3.16.7-ckt11-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"linux-compiler-gcc-4.9-x86", reference:"3.16.7-ckt11-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"linux-doc-3.16", reference:"3.16.7-ckt11-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"linux-headers-3.16.0-9-586", reference:"3.16.7-ckt11-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"linux-headers-3.16.0-9-686-pae", reference:"3.16.7-ckt11-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"linux-headers-3.16.0-9-all", reference:"3.16.7-ckt11-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"linux-headers-3.16.0-9-all-amd64", reference:"3.16.7-ckt11-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"linux-headers-3.16.0-9-all-armel", reference:"3.16.7-ckt11-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"linux-headers-3.16.0-9-all-armhf", reference:"3.16.7-ckt11-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"linux-headers-3.16.0-9-all-i386", reference:"3.16.7-ckt11-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"linux-headers-3.16.0-9-amd64", reference:"3.16.7-ckt11-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"linux-headers-3.16.0-9-armmp", reference:"3.16.7-ckt11-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"linux-headers-3.16.0-9-armmp-lpae", reference:"3.16.7-ckt11-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"linux-headers-3.16.0-9-common", reference:"3.16.7-ckt11-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"linux-headers-3.16.0-9-ixp4xx", reference:"3.16.7-ckt11-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"linux-headers-3.16.0-9-kirkwood", reference:"3.16.7-ckt11-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"linux-headers-3.16.0-9-orion5x", reference:"3.16.7-ckt11-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"linux-headers-3.16.0-9-versatile", reference:"3.16.7-ckt11-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"linux-image-3.16.0-9-586", reference:"3.16.7-ckt11-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"linux-image-3.16.0-9-686-pae", reference:"3.16.7-ckt11-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"linux-image-3.16.0-9-686-pae-dbg", reference:"3.16.7-ckt11-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"linux-image-3.16.0-9-amd64", reference:"3.16.7-ckt11-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"linux-image-3.16.0-9-amd64-dbg", reference:"3.16.7-ckt11-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"linux-image-3.16.0-9-armmp", reference:"3.16.7-ckt11-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"linux-image-3.16.0-9-armmp-lpae", reference:"3.16.7-ckt11-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"linux-image-3.16.0-9-ixp4xx", reference:"3.16.7-ckt11-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"linux-image-3.16.0-9-kirkwood", reference:"3.16.7-ckt11-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"linux-image-3.16.0-9-orion5x", reference:"3.16.7-ckt11-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"linux-image-3.16.0-9-versatile", reference:"3.16.7-ckt11-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"linux-libc-dev", reference:"3.16.7-ckt11-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"linux-manual-3.16", reference:"3.16.7-ckt11-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"linux-source-3.16", reference:"3.16.7-ckt11-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"linux-support-3.16.0-9", reference:"3.16.7-ckt11-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"xen-linux-system-3.16.0-9-amd64", reference:"3.16.7-ckt11-1+deb8u2")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
