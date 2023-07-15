#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-3945. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(102550);
  script_version("3.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2014-9940", "CVE-2017-1000363", "CVE-2017-1000365", "CVE-2017-10911", "CVE-2017-11176", "CVE-2017-7346", "CVE-2017-7482", "CVE-2017-7533", "CVE-2017-7541", "CVE-2017-7542", "CVE-2017-7889", "CVE-2017-9605");
  script_xref(name:"DSA", value:"3945");

  script_name(english:"Debian DSA-3945-1 : linux - security update (Stack Clash)");
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

  - CVE-2014-9940
    A use-after-free flaw in the voltage and current
    regulator driver could allow a local user to cause a
    denial of service or potentially escalate privileges.

  - CVE-2017-7346
    Li Qiang discovered that the DRM driver for VMware
    virtual GPUs does not properly check user-controlled
    values in the vmw_surface_define_ioctl() functions for
    upper limits. A local user can take advantage of this
    flaw to cause a denial of service.

  - CVE-2017-7482
    Shi Lei discovered that RxRPC Kerberos 5 ticket handling
    code does not properly verify metadata, leading to
    information disclosure, denial of service or potentially
    execution of arbitrary code.

  - CVE-2017-7533
    Fan Wu and Shixiong Zhao discovered a race condition
    between inotify events and VFS rename operations
    allowing an unprivileged local attacker to cause a
    denial of service or escalate privileges.

  - CVE-2017-7541
    A buffer overflow flaw in the Broadcom IEEE802.11n PCIe
    SoftMAC WLAN driver could allow a local user to cause
    kernel memory corruption, leading to a denial of service
    or potentially privilege escalation.

  - CVE-2017-7542
    An integer overflow vulnerability in the
    ip6_find_1stfragopt() function was found allowing a
    local attacker with privileges to open raw sockets to
    cause a denial of service.

  - CVE-2017-7889
    Tommi Rantala and Brad Spengler reported that the mm
    subsystem does not properly enforce the
    CONFIG_STRICT_DEVMEM protection mechanism, allowing a
    local attacker with access to /dev/mem to obtain
    sensitive information or potentially execute arbitrary
    code.

  - CVE-2017-9605
    Murray McAllister discovered that the DRM driver for
    VMware virtual GPUs does not properly initialize memory,
    potentially allowing a local attacker to obtain
    sensitive information from uninitialized kernel memory
    via a crafted ioctl call.

  - CVE-2017-10911
    / XSA-216

  Anthony Perard of Citrix discovered an information leak flaw in Xen
  blkif response handling, allowing a malicious unprivileged guest to
  obtain sensitive information from the host or other guests.

  - CVE-2017-11176
    It was discovered that the mq_notify() function does not
    set the sock pointer to NULL upon entry into the retry
    logic. An attacker can take advantage of this flaw
    during a userspace close of a Netlink socket to cause a
    denial of service or potentially cause other impact.

  - CVE-2017-1000363
    Roee Hay reported that the lp driver does not properly
    bounds-check passed arguments, allowing a local attacker
    with write access to the kernel command line arguments
    to execute arbitrary code.

  - CVE-2017-1000365
    It was discovered that argument and environment pointers
    are not taken properly into account to the imposed size
    restrictions on arguments and environmental strings
    passed through RLIMIT_STACK/RLIMIT_INFINITY. A local
    attacker can take advantage of this flaw in conjunction
    with other flaws to execute arbitrary code."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2014-9940"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2017-7346"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2017-7482"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2017-7533"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2017-7541"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2017-7542"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2017-7889"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2017-9605"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2017-10911"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2017-11176"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2017-1000363"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2017-1000365"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/jessie/linux"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.debian.org/security/2017/dsa-3945"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the linux packages.

For the oldstable distribution (jessie), these problems have been
fixed in version 3.16.43-2+deb8u3."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:8.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/03/30");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/08/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/08/18");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_set_attribute(attribute:"generated_plugin", value:"current");
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
if (deb_check(release:"8.0", prefix:"linux-compiler-gcc-4.8-arm", reference:"3.16.43-2+deb8u3")) flag++;
if (deb_check(release:"8.0", prefix:"linux-compiler-gcc-4.8-x86", reference:"3.16.43-2+deb8u3")) flag++;
if (deb_check(release:"8.0", prefix:"linux-compiler-gcc-4.9-x86", reference:"3.16.43-2+deb8u3")) flag++;
if (deb_check(release:"8.0", prefix:"linux-doc-3.16", reference:"3.16.43-2+deb8u3")) flag++;
if (deb_check(release:"8.0", prefix:"linux-headers-3.16.0-9-586", reference:"3.16.43-2+deb8u3")) flag++;
if (deb_check(release:"8.0", prefix:"linux-headers-3.16.0-9-686-pae", reference:"3.16.43-2+deb8u3")) flag++;
if (deb_check(release:"8.0", prefix:"linux-headers-3.16.0-9-all", reference:"3.16.43-2+deb8u3")) flag++;
if (deb_check(release:"8.0", prefix:"linux-headers-3.16.0-9-all-amd64", reference:"3.16.43-2+deb8u3")) flag++;
if (deb_check(release:"8.0", prefix:"linux-headers-3.16.0-9-all-armel", reference:"3.16.43-2+deb8u3")) flag++;
if (deb_check(release:"8.0", prefix:"linux-headers-3.16.0-9-all-armhf", reference:"3.16.43-2+deb8u3")) flag++;
if (deb_check(release:"8.0", prefix:"linux-headers-3.16.0-9-all-i386", reference:"3.16.43-2+deb8u3")) flag++;
if (deb_check(release:"8.0", prefix:"linux-headers-3.16.0-9-amd64", reference:"3.16.43-2+deb8u3")) flag++;
if (deb_check(release:"8.0", prefix:"linux-headers-3.16.0-9-armmp", reference:"3.16.43-2+deb8u3")) flag++;
if (deb_check(release:"8.0", prefix:"linux-headers-3.16.0-9-armmp-lpae", reference:"3.16.43-2+deb8u3")) flag++;
if (deb_check(release:"8.0", prefix:"linux-headers-3.16.0-9-common", reference:"3.16.43-2+deb8u3")) flag++;
if (deb_check(release:"8.0", prefix:"linux-headers-3.16.0-9-ixp4xx", reference:"3.16.43-2+deb8u3")) flag++;
if (deb_check(release:"8.0", prefix:"linux-headers-3.16.0-9-kirkwood", reference:"3.16.43-2+deb8u3")) flag++;
if (deb_check(release:"8.0", prefix:"linux-headers-3.16.0-9-orion5x", reference:"3.16.43-2+deb8u3")) flag++;
if (deb_check(release:"8.0", prefix:"linux-headers-3.16.0-9-versatile", reference:"3.16.43-2+deb8u3")) flag++;
if (deb_check(release:"8.0", prefix:"linux-image-3.16.0-9-586", reference:"3.16.43-2+deb8u3")) flag++;
if (deb_check(release:"8.0", prefix:"linux-image-3.16.0-9-686-pae", reference:"3.16.43-2+deb8u3")) flag++;
if (deb_check(release:"8.0", prefix:"linux-image-3.16.0-9-686-pae-dbg", reference:"3.16.43-2+deb8u3")) flag++;
if (deb_check(release:"8.0", prefix:"linux-image-3.16.0-9-amd64", reference:"3.16.43-2+deb8u3")) flag++;
if (deb_check(release:"8.0", prefix:"linux-image-3.16.0-9-amd64-dbg", reference:"3.16.43-2+deb8u3")) flag++;
if (deb_check(release:"8.0", prefix:"linux-image-3.16.0-9-armmp", reference:"3.16.43-2+deb8u3")) flag++;
if (deb_check(release:"8.0", prefix:"linux-image-3.16.0-9-armmp-lpae", reference:"3.16.43-2+deb8u3")) flag++;
if (deb_check(release:"8.0", prefix:"linux-image-3.16.0-9-ixp4xx", reference:"3.16.43-2+deb8u3")) flag++;
if (deb_check(release:"8.0", prefix:"linux-image-3.16.0-9-kirkwood", reference:"3.16.43-2+deb8u3")) flag++;
if (deb_check(release:"8.0", prefix:"linux-image-3.16.0-9-orion5x", reference:"3.16.43-2+deb8u3")) flag++;
if (deb_check(release:"8.0", prefix:"linux-image-3.16.0-9-versatile", reference:"3.16.43-2+deb8u3")) flag++;
if (deb_check(release:"8.0", prefix:"linux-libc-dev", reference:"3.16.43-2+deb8u3")) flag++;
if (deb_check(release:"8.0", prefix:"linux-manual-3.16", reference:"3.16.43-2+deb8u3")) flag++;
if (deb_check(release:"8.0", prefix:"linux-source-3.16", reference:"3.16.43-2+deb8u3")) flag++;
if (deb_check(release:"8.0", prefix:"linux-support-3.16.0-9", reference:"3.16.43-2+deb8u3")) flag++;
if (deb_check(release:"8.0", prefix:"xen-linux-system-3.16.0-9-amd64", reference:"3.16.43-2+deb8u3")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
