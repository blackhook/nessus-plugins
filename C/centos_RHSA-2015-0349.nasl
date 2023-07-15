#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2015:0349 and 
# CentOS Errata and Security Advisory 2015:0349 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(81891);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2014-3640", "CVE-2014-7815", "CVE-2014-7840", "CVE-2014-8106");
  script_xref(name:"RHSA", value:"2015:0349");

  script_name(english:"CentOS 7 : qemu-kvm (CESA-2015:0349)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated qemu-kvm packages that fix multiple security issues, several
bugs, and add various enhancements are now available for Red Hat
Enterprise Linux 7.

Red Hat Product Security has rated this update as having Important
security impact. Common Vulnerability Scoring System (CVSS) base
scores, which give detailed severity ratings, are available for each
vulnerability from the CVE links in the References section.

KVM (Kernel-based Virtual Machine) is a full virtualization solution
for Linux on AMD64 and Intel 64 systems. The qemu-kvm packages provide
the user-space component for running virtual machines using KVM.

It was found that the Cirrus blit region checks were insufficient. A
privileged guest user could use this flaw to write outside of
VRAM-allocated buffer boundaries in the host's QEMU process address
space with attacker-provided data. (CVE-2014-8106)

An uninitialized data structure use flaw was found in the way the
set_pixel_format() function sanitized the value of bits_per_pixel. An
attacker able to access a guest's VNC console could use this flaw to
crash the guest. (CVE-2014-7815)

It was found that certain values that were read when loading RAM
during migration were not validated. A user able to alter the savevm
data (either on the disk or over the wire during migration) could use
either of these flaws to corrupt QEMU process memory on the
(destination) host, which could potentially result in arbitrary code
execution on the host with the privileges of the QEMU process.
(CVE-2014-7840)

A NULL pointer dereference flaw was found in the way QEMU handled UDP
packets with a source port and address of 0 when QEMU's user
networking was in use. A local guest user could use this flaw to crash
the guest. (CVE-2014-3640)

Red Hat would like to thank James Spadaro of Cisco for reporting
CVE-2014-7815, and Xavier Mehrenberger and Stephane Duverger of Airbus
for reporting CVE-2014-3640. The CVE-2014-8106 issue was found by
Paolo Bonzini of Red Hat, and the CVE-2014-7840 issue was discovered
by Michael S. Tsirkin of Red Hat.

Bug fixes :

* The KVM utility executed demanding routing update system calls every
time it performed an MSI vector mask/unmask operation. Consequently,
guests running legacy systems such as Red Hat Enterprise Linux 5
could, under certain circumstances, experience significant slowdown.
Now, the routing system calls during mask/unmask operations are
skipped, and the performance of legacy guests is now more consistent.
(BZ#1098976)

* Due to a bug in the Internet Small Computer System Interface (iSCSI)
driver, a qemu-kvm process terminated unexpectedly with a segmentation
fault when the 'write same' command was executed in guest mode under
the iSCSI protocol. This update fixes the bug, and the 'write same'
command now functions in guest mode under iSCSI as intended.
(BZ#1083413)

* The QEMU command interface did not properly handle resizing of cache
memory during guest migration, causing QEMU to terminate unexpectedly
with a segmentation fault. This update fixes the related code, and
QEMU no longer crashes in the described situation. (BZ#1066338)

Enhancements :

* The maximum number of supported virtual CPUs (vCPUs) in a KVM guest
has been increased to 240. This increases the number of virtual
processing units that the user can assign to the guest, and therefore
improves its performance potential. (BZ#1134408)

* Support for the 5th Generation Intel Core processors has been added
to the QEMU hypervisor, the KVM kernel code, and the libvirt API. This
allows KVM guests to use the following instructions and features:
ADCX, ADOX, RDSFEED, PREFETCHW, and supervisor mode access prevention
(SMAP). (BZ#1116117)

* The 'dump-guest-memory' command now supports crash dump compression.
This makes it possible for users who cannot use the 'virsh dump'
command to require less hard disk space for guest crash dumps. In
addition, saving a compressed guest crash dump frequently takes less
time than saving a non-compressed one. (BZ#1157798)

* This update introduces support for flight recorder tracing, which
uses SystemTap to automatically capture qemu-kvm data while the guest
machine is running. For detailed instructions on how to configure and
use flight recorder tracing, see the Virtualization Deployment and
Administration Guide, linked to in the References section below.
(BZ#1088112)"
  );
  # https://lists.centos.org/pipermail/centos-cr-announce/2015-March/001773.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?a6e8c1d0"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected qemu-kvm packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2014-7840");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libcacard");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libcacard-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libcacard-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:qemu-img");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:qemu-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:qemu-kvm-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:qemu-kvm-tools");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:7");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/11/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/03/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/03/18");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"CentOS Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/CentOS/release", "Host/CentOS/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/CentOS/release");
if (isnull(release) || "CentOS" >!< release) audit(AUDIT_OS_NOT, "CentOS");
os_ver = pregmatch(pattern: "CentOS(?: Linux)? release ([0-9]+)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "CentOS");
os_ver = os_ver[1];
if (! preg(pattern:"^7([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "CentOS 7.x", "CentOS " + os_ver);

if (!get_kb_item("Host/CentOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "CentOS", cpu);


flag = 0;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libcacard-1.5.3-86.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libcacard-devel-1.5.3-86.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libcacard-tools-1.5.3-86.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"qemu-img-1.5.3-86.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"qemu-kvm-1.5.3-86.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"qemu-kvm-common-1.5.3-86.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"qemu-kvm-tools-1.5.3-86.el7")) flag++;


if (flag)
{
  cr_plugin_caveat = '\n' +
    'NOTE: The security advisory associated with this vulnerability has a\n' +
    'fixed package version that may only be available in the continuous\n' +
    'release (CR) repository for CentOS, until it is present in the next\n' +
    'point release of CentOS.\n\n' +

    'If an equal or higher package level does not exist in the baseline\n' +
    'repository for your major version of CentOS, then updates from the CR\n' +
    'repository will need to be applied in order to address the\n' +
    'vulnerability.\n';
  security_report_v4(
    port       : 0,
    severity   : SECURITY_HOLE,
    extra      : rpm_report_get() + cr_plugin_caveat
  );
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libcacard / libcacard-devel / libcacard-tools / qemu-img / qemu-kvm / etc");
}
