#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2014:0420 and 
# Oracle Linux Security Advisory ELSA-2014-0420 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(73662);
  script_version("1.14");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2014-0142", "CVE-2014-0143", "CVE-2014-0144", "CVE-2014-0145", "CVE-2014-0146", "CVE-2014-0147", "CVE-2014-0148", "CVE-2014-0150");
  script_bugtraq_id(66464, 66472, 66480, 66481, 66483, 66484, 66486, 66821);
  script_xref(name:"RHSA", value:"2014:0420");

  script_name(english:"Oracle Linux 6 : qemu-kvm (ELSA-2014-0420)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Oracle Linux host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"From Red Hat Security Advisory 2014:0420 :

Updated qemu-kvm packages that fix multiple security issues are now
available for Red Hat Enterprise Linux 6.

The Red Hat Security Response Team has rated this update as having
Moderate security impact. Common Vulnerability Scoring System (CVSS)
base scores, which give detailed severity ratings, are available for
each vulnerability from the CVE links in the References section.

KVM (Kernel-based Virtual Machine) is a full virtualization solution
for Linux on AMD64 and Intel 64 systems. The qemu-kvm package provides
the user-space component for running virtual machines using KVM.

Multiple integer overflow, input validation, logic error, and buffer
overflow flaws were discovered in various QEMU block drivers. An
attacker able to modify a disk image file loaded by a guest could use
these flaws to crash the guest, or corrupt QEMU process memory on the
host, potentially resulting in arbitrary code execution on the host
with the privileges of the QEMU process. (CVE-2014-0143,
CVE-2014-0144, CVE-2014-0145, CVE-2014-0147)

A buffer overflow flaw was found in the way the
virtio_net_handle_mac() function of QEMU processed guest requests to
update the table of MAC addresses. A privileged guest user could use
this flaw to corrupt QEMU process memory on the host, potentially
resulting in arbitrary code execution on the host with the privileges
of the QEMU process. (CVE-2014-0150)

A divide-by-zero flaw was found in the seek_to_sector() function of
the parallels block driver in QEMU. An attacker able to modify a disk
image file loaded by a guest could use this flaw to crash the guest.
(CVE-2014-0142)

A NULL pointer dereference flaw was found in the QCOW2 block driver in
QEMU. An attacker able to modify a disk image file loaded by a guest
could use this flaw to crash the guest. (CVE-2014-0146)

It was found that the block driver for Hyper-V VHDX images did not
correctly calculate BAT (Block Allocation Table) entries due to a
missing bounds check. An attacker able to modify a disk image file
loaded by a guest could use this flaw to crash the guest.
(CVE-2014-0148)

The CVE-2014-0143 issues were discovered by Kevin Wolf and Stefan
Hajnoczi of Red Hat, the CVE-2014-0144 issues were discovered by Fam
Zheng, Jeff Cody, Kevin Wolf, and Stefan Hajnoczi of Red Hat, the
CVE-2014-0145 issues were discovered by Stefan Hajnoczi of Red Hat,
the CVE-2014-0150 issue was discovered by Michael S. Tsirkin of Red
Hat, the CVE-2014-0142, CVE-2014-0146, and CVE-2014-0147 issues were
discovered by Kevin Wolf of Red Hat, and the CVE-2014-0148 issue was
discovered by Jeff Cody of Red Hat.

All qemu-kvm users are advised to upgrade to these updated packages,
which contain backported patches to correct these issues. After
installing this update, shut down all running virtual machines. Once
all virtual machines have shut down, start them again for this update
to take effect."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2014-April/004084.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected qemu-kvm packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:A/AC:M/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:qemu-guest-agent");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:qemu-img");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:qemu-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:qemu-kvm-tools");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:6");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/04/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/04/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/04/23");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"Oracle Linux Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/OracleLinux", "Host/RedHat/release", "Host/RedHat/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/OracleLinux")) audit(AUDIT_OS_NOT, "Oracle Linux");
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || !pregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux)", string:release)) audit(AUDIT_OS_NOT, "Oracle Linux");
os_ver = pregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux) .*release ([0-9]+(\.[0-9]+)?)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Oracle Linux");
os_ver = os_ver[1];
if (! preg(pattern:"^6([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Oracle Linux 6", "Oracle Linux " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Oracle Linux", cpu);

flag = 0;
if (rpm_check(release:"EL6", reference:"qemu-guest-agent-0.12.1.2-2.415.el6_5.8")) flag++;
if (rpm_check(release:"EL6", cpu:"x86_64", reference:"qemu-img-0.12.1.2-2.415.el6_5.8")) flag++;
if (rpm_check(release:"EL6", cpu:"x86_64", reference:"qemu-kvm-0.12.1.2-2.415.el6_5.8")) flag++;
if (rpm_check(release:"EL6", cpu:"x86_64", reference:"qemu-kvm-tools-0.12.1.2-2.415.el6_5.8")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "qemu-guest-agent / qemu-img / qemu-kvm / qemu-kvm-tools");
}
