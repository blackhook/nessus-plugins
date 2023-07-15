#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-3060. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(78784);
  script_version("1.15");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/11");

  script_cve_id("CVE-2014-3610", "CVE-2014-3611", "CVE-2014-3645", "CVE-2014-3646", "CVE-2014-3647", "CVE-2014-3673", "CVE-2014-3687", "CVE-2014-3688", "CVE-2014-3690", "CVE-2014-7207");
  script_bugtraq_id(70691, 70742, 70743, 70745, 70746, 70748, 70766, 70768, 70867);
  script_xref(name:"DSA", value:"3060");

  script_name(english:"Debian DSA-3060-1 : linux - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several vulnerabilities have been discovered in the Linux kernel that
may lead to a denial of service :

  - CVE-2014-3610
    Lars Bull of Google and Nadav Amit reported a flaw in
    how KVM handles noncanonical writes to certain MSR
    registers. A privileged guest user can exploit this flaw
    to cause a denial of service (kernel panic) on the host.

  - CVE-2014-3611
    Lars Bull of Google reported a race condition in the PIT
    emulation code in KVM. A local guest user with access to
    PIT i/o ports could exploit this flaw to cause a denial
    of service (crash) on the host.

  - CVE-2014-3645/ CVE-2014-3646
    The Advanced Threat Research team at Intel Security
    discovered that the KVM subsystem did not handle the VM
    exits gracefully for the invept (Invalidate Translations
    Derived from EPT) and invvpid (Invalidate Translations
    Based on VPID) instructions. On hosts with an Intel
    processor and invept/invppid VM exit support, an
    unprivileged guest user could use these instructions to
    crash the guest.

  - CVE-2014-3647
    Nadav Amit reported that KVM mishandles noncanonical
    addresses when emulating instructions that change rip,
    potentially causing a failed VM-entry. A guest user with
    access to I/O or the MMIO can use this flaw to cause a
    denial of service (system crash) of the guest.

  - CVE-2014-3673
    Liu Wei of Red Hat discovered a flaw in
    net/core/skbuff.c leading to a kernel panic when
    receiving malformed ASCONF chunks. A remote attacker
    could use this flaw to crash the system.

  - CVE-2014-3687
    A flaw in the sctp stack was discovered leading to a
    kernel panic when receiving duplicate ASCONF chunks. A
    remote attacker could use this flaw to crash the system.

  - CVE-2014-3688
    It was found that the sctp stack is prone to a remotely
    triggerable memory pressure issue caused by excessive
    queueing. A remote attacker could use this flaw to cause
    denial-of-service conditions on the system.

  - CVE-2014-3690
    Andy Lutomirski discovered that incorrect register
    handling in KVM may lead to denial of service.

  - CVE-2014-7207
    Several Debian developers reported an issue in the IPv6
    networking subsystem. A local user with access to tun or
    macvtap devices, or a virtual machine connected to such
    a device, can cause a denial of service (system crash).

This update includes a bug fix related to CVE-2014-7207 that disables
UFO (UDP Fragmentation Offload) in the macvtap, tun, and virtio_net
drivers. This will cause migration of a running VM from a host running
an earlier kernel version to a host running this kernel version to
fail, if the VM has been assigned a virtio network device. In order to
migrate such a VM, it must be shut down first."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=766195"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2014-3610"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2014-3611"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2014-3645"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2014-3646"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2014-3647"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2014-3673"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2014-3687"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2014-3688"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2014-3690"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2014-7207"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2014-7207"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.debian.org/security/2014/dsa-3060"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the linux packages.

For the stable distribution (wheezy), these problems have been fixed
in version 3.2.63-2+deb7u1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:7.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/11/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/10/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/11/03");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (deb_check(release:"7.0", prefix:"linux", reference:"3.2.63-2+deb7u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
