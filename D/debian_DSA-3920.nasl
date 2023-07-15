#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-3920. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(101985);
  script_version("3.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2017-10664", "CVE-2017-10911", "CVE-2017-9310", "CVE-2017-9330", "CVE-2017-9373", "CVE-2017-9374");
  script_xref(name:"DSA", value:"3920");

  script_name(english:"Debian DSA-3920-1 : qemu - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Multiple vulnerabilities were found in qemu, a fast processor emulator
:

  - CVE-2017-9310
    Denial of service via infinite loop in e1000e NIC
    emulation.

  - CVE-2017-9330
    Denial of service via infinite loop in USB OHCI
    emulation.

  - CVE-2017-9373
    Denial of service via memory leak in IDE AHCI emulation.

  - CVE-2017-9374
    Denial of service via memory leak in USB EHCI emulation.

  - CVE-2017-10664
    Denial of service in qemu-nbd server.

  - CVE-2017-10911
    Information leak in Xen blkif response handling."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2017-9310"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2017-9330"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2017-9373"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2017-9374"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2017-10664"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2017-10911"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/stretch/qemu"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.debian.org/security/2017/dsa-3920"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the qemu packages.

For the oldstable distribution (jessie), a separate DSA will be
issued.

For the stable distribution (stretch), these problems have been fixed
in version 1:2.8+dfsg-6+deb9u1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:qemu");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:9.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/07/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/07/27");
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
if (deb_check(release:"9.0", prefix:"qemu", reference:"1:2.8+dfsg-6+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"qemu-block-extra", reference:"1:2.8+dfsg-6+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"qemu-guest-agent", reference:"1:2.8+dfsg-6+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"qemu-kvm", reference:"1:2.8+dfsg-6+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"qemu-system", reference:"1:2.8+dfsg-6+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"qemu-system-arm", reference:"1:2.8+dfsg-6+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"qemu-system-common", reference:"1:2.8+dfsg-6+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"qemu-system-mips", reference:"1:2.8+dfsg-6+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"qemu-system-misc", reference:"1:2.8+dfsg-6+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"qemu-system-ppc", reference:"1:2.8+dfsg-6+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"qemu-system-sparc", reference:"1:2.8+dfsg-6+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"qemu-system-x86", reference:"1:2.8+dfsg-6+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"qemu-user", reference:"1:2.8+dfsg-6+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"qemu-user-binfmt", reference:"1:2.8+dfsg-6+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"qemu-user-static", reference:"1:2.8+dfsg-6+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"qemu-utils", reference:"1:2.8+dfsg-6+deb9u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
