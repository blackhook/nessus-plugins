#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-3448. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(87995);
  script_version("2.13");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/11");

  script_cve_id("CVE-2013-4312", "CVE-2015-7566", "CVE-2015-8767", "CVE-2016-0723", "CVE-2016-0728");
  script_xref(name:"DSA", value:"3448");

  script_name(english:"Debian DSA-3448-1 : linux - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several vulnerabilities have been discovered in the Linux kernel that
may lead to a privilege escalation or denial-of-service.

  - CVE-2013-4312
    Tetsuo Handa discovered that it is possible for a
    process to open far more files than the process' limit
    leading to denial-of-service conditions.

  - CVE-2015-7566
    Ralf Spenneberg of OpenSource Security reported that the
    visor driver crashes when a specially crafted USB device
    without bulk-out endpoint is detected.

  - CVE-2015-8767
    An SCTP denial-of-service was discovered which can be
    triggered by a local attacker during a heartbeat timeout
    event after the 4-way handshake.

  - CVE-2016-0723
    A use-after-free vulnerability was discovered in the
    TIOCGETD ioctl. A local attacker could use this flaw for
    denial-of-service.

  - CVE-2016-0728
    The Perception Point research team discovered a
    use-after-free vulnerability in the keyring facility,
    possibly leading to local privilege escalation."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2013-4312"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2015-7566"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2015-8767"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2016-0723"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2016-0728"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/jessie/linux"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.debian.org/security/2016/dsa-3448"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the linux packages.

For the stable distribution (jessie), these problems have been fixed
in version 3.16.7-ckt20-1+deb8u3."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:8.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/02/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/01/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/01/20");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (deb_check(release:"8.0", prefix:"linux-compiler-gcc-4.8-arm", reference:"3.16.7-ckt20-1+deb8u3")) flag++;
if (deb_check(release:"8.0", prefix:"linux-compiler-gcc-4.8-x86", reference:"3.16.7-ckt20-1+deb8u3")) flag++;
if (deb_check(release:"8.0", prefix:"linux-compiler-gcc-4.9-x86", reference:"3.16.7-ckt20-1+deb8u3")) flag++;
if (deb_check(release:"8.0", prefix:"linux-doc-3.16", reference:"3.16.7-ckt20-1+deb8u3")) flag++;
if (deb_check(release:"8.0", prefix:"linux-headers-3.16.0-9-586", reference:"3.16.7-ckt20-1+deb8u3")) flag++;
if (deb_check(release:"8.0", prefix:"linux-headers-3.16.0-9-686-pae", reference:"3.16.7-ckt20-1+deb8u3")) flag++;
if (deb_check(release:"8.0", prefix:"linux-headers-3.16.0-9-all", reference:"3.16.7-ckt20-1+deb8u3")) flag++;
if (deb_check(release:"8.0", prefix:"linux-headers-3.16.0-9-all-amd64", reference:"3.16.7-ckt20-1+deb8u3")) flag++;
if (deb_check(release:"8.0", prefix:"linux-headers-3.16.0-9-all-armel", reference:"3.16.7-ckt20-1+deb8u3")) flag++;
if (deb_check(release:"8.0", prefix:"linux-headers-3.16.0-9-all-armhf", reference:"3.16.7-ckt20-1+deb8u3")) flag++;
if (deb_check(release:"8.0", prefix:"linux-headers-3.16.0-9-all-i386", reference:"3.16.7-ckt20-1+deb8u3")) flag++;
if (deb_check(release:"8.0", prefix:"linux-headers-3.16.0-9-amd64", reference:"3.16.7-ckt20-1+deb8u3")) flag++;
if (deb_check(release:"8.0", prefix:"linux-headers-3.16.0-9-armmp", reference:"3.16.7-ckt20-1+deb8u3")) flag++;
if (deb_check(release:"8.0", prefix:"linux-headers-3.16.0-9-armmp-lpae", reference:"3.16.7-ckt20-1+deb8u3")) flag++;
if (deb_check(release:"8.0", prefix:"linux-headers-3.16.0-9-common", reference:"3.16.7-ckt20-1+deb8u3")) flag++;
if (deb_check(release:"8.0", prefix:"linux-headers-3.16.0-9-ixp4xx", reference:"3.16.7-ckt20-1+deb8u3")) flag++;
if (deb_check(release:"8.0", prefix:"linux-headers-3.16.0-9-kirkwood", reference:"3.16.7-ckt20-1+deb8u3")) flag++;
if (deb_check(release:"8.0", prefix:"linux-headers-3.16.0-9-orion5x", reference:"3.16.7-ckt20-1+deb8u3")) flag++;
if (deb_check(release:"8.0", prefix:"linux-headers-3.16.0-9-versatile", reference:"3.16.7-ckt20-1+deb8u3")) flag++;
if (deb_check(release:"8.0", prefix:"linux-image-3.16.0-9-586", reference:"3.16.7-ckt20-1+deb8u3")) flag++;
if (deb_check(release:"8.0", prefix:"linux-image-3.16.0-9-686-pae", reference:"3.16.7-ckt20-1+deb8u3")) flag++;
if (deb_check(release:"8.0", prefix:"linux-image-3.16.0-9-686-pae-dbg", reference:"3.16.7-ckt20-1+deb8u3")) flag++;
if (deb_check(release:"8.0", prefix:"linux-image-3.16.0-9-amd64", reference:"3.16.7-ckt20-1+deb8u3")) flag++;
if (deb_check(release:"8.0", prefix:"linux-image-3.16.0-9-amd64-dbg", reference:"3.16.7-ckt20-1+deb8u3")) flag++;
if (deb_check(release:"8.0", prefix:"linux-image-3.16.0-9-armmp", reference:"3.16.7-ckt20-1+deb8u3")) flag++;
if (deb_check(release:"8.0", prefix:"linux-image-3.16.0-9-armmp-lpae", reference:"3.16.7-ckt20-1+deb8u3")) flag++;
if (deb_check(release:"8.0", prefix:"linux-image-3.16.0-9-ixp4xx", reference:"3.16.7-ckt20-1+deb8u3")) flag++;
if (deb_check(release:"8.0", prefix:"linux-image-3.16.0-9-kirkwood", reference:"3.16.7-ckt20-1+deb8u3")) flag++;
if (deb_check(release:"8.0", prefix:"linux-image-3.16.0-9-orion5x", reference:"3.16.7-ckt20-1+deb8u3")) flag++;
if (deb_check(release:"8.0", prefix:"linux-image-3.16.0-9-versatile", reference:"3.16.7-ckt20-1+deb8u3")) flag++;
if (deb_check(release:"8.0", prefix:"linux-libc-dev", reference:"3.16.7-ckt20-1+deb8u3")) flag++;
if (deb_check(release:"8.0", prefix:"linux-manual-3.16", reference:"3.16.7-ckt20-1+deb8u3")) flag++;
if (deb_check(release:"8.0", prefix:"linux-source-3.16", reference:"3.16.7-ckt20-1+deb8u3")) flag++;
if (deb_check(release:"8.0", prefix:"linux-support-3.16.0-9", reference:"3.16.7-ckt20-1+deb8u3")) flag++;
if (deb_check(release:"8.0", prefix:"xen-linux-system-3.16.0-9-amd64", reference:"3.16.7-ckt20-1+deb8u3")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
