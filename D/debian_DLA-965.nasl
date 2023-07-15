#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-965-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(100514);
  script_version("3.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/11");

  script_cve_id("CVE-2016-9602", "CVE-2017-7377", "CVE-2017-7471", "CVE-2017-7493", "CVE-2017-8086");

  script_name(english:"Debian DLA-965-1 : qemu-kvm security update");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several vulnerabilities were discovered in qemu-kvm, a full
virtualization solution for Linux hosts on x86 hardware with x86
guests based on the Quick Emulator(Qemu).

CVE-2016-9602

Quick Emulator(Qemu) built with the VirtFS, host directory sharing via
Plan 9 File System(9pfs) support, is vulnerable to an improper link
following issue. It could occur while accessing symbolic link files on
a shared host directory.

A privileged user inside guest could use this flaw to access
host file system beyond the shared folder and potentially
escalating their privileges on a host.

CVE-2017-7377

Quick Emulator(Qemu) built with the virtio-9p back-end support is
vulnerable to a memory leakage issue. It could occur while doing a I/O
operation via v9fs_create/v9fs_lcreate routine.

A privileged user/process inside guest could use this flaw
to leak host memory resulting in Dos.

CVE-2017-7471

Quick Emulator(Qemu) built with the VirtFS, host directory sharing via
Plan 9 File System(9pfs) support, is vulnerable to an improper access
control issue. It could occur while accessing files on a shared host
directory.

A privileged user inside guest could use this flaw to access
host file system beyond the shared folder and potentially
escalating their privileges on a host.

CVE-2017-7493

Quick Emulator(Qemu) built with the VirtFS, host directory sharing via
Plan 9 File System(9pfs) support, is vulnerable to an improper access
control issue. It could occur while accessing virtfs metadata files in
mapped-file security mode.

A guest user could use this flaw to escalate their
privileges inside guest.

CVE-2017-8086

Quick Emulator(Qemu) built with the virtio-9p back-end support is
vulnerable to a memory leakage issue. It could occur while querying
file system extended attributes via 9pfs_list_xattr() routine.

A privileged user/process inside guest could use this flaw
to leak host memory resulting in Dos. For Debian 7 'Wheezy',
these problems have been fixed in version
1.1.2+dfsg-6+deb7u22.

We recommend that you upgrade your qemu-kvm packages.

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2017/05/msg00040.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/wheezy/qemu-kvm"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Upgrade the affected kvm, qemu-kvm, and qemu-kvm-dbg packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:qemu-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:qemu-kvm-dbg");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:7.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/05/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/05/31");
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
if (deb_check(release:"7.0", prefix:"kvm", reference:"1.1.2+dfsg-6+deb7u22")) flag++;
if (deb_check(release:"7.0", prefix:"qemu-kvm", reference:"1.1.2+dfsg-6+deb7u22")) flag++;
if (deb_check(release:"7.0", prefix:"qemu-kvm-dbg", reference:"1.1.2+dfsg-6+deb7u22")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
