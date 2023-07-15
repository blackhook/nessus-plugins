#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux 2 Security Advisory ALAS-2019-1274.
#

include("compat.inc");

if (description)
{
  script_id(128288);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/06");

  script_cve_id("CVE-2018-12126", "CVE-2018-12127", "CVE-2018-12130", "CVE-2019-10132", "CVE-2019-10161", "CVE-2019-10166", "CVE-2019-10167", "CVE-2019-10168", "CVE-2019-11091");
  script_xref(name:"ALAS", value:"2019-1274");
  script_xref(name:"CEA-ID", value:"CEA-2019-0547");
  script_xref(name:"CEA-ID", value:"CEA-2019-0324");

  script_name(english:"Amazon Linux 2 : libvirt (ALAS-2019-1274) (MDSUM/RIDL) (MFBDS/RIDL/ZombieLoad) (MLPDS/RIDL) (MSBDS/Fallout)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote Amazon Linux 2 host is missing a security update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"Uncacheable memory on some microprocessors utilizing speculative
execution may allow an authenticated user to potentially enable
information disclosure via a side channel with local access.
(CVE-2019-11091)

Modern Intel microprocessors implement hardware-level
micro-optimizations to improve the performance of writing data back to
CPU caches. The write operation is split into STA (STore Address) and
STD (STore Data) sub-operations. These sub-operations allow the
processor to hand-off address generation logic into these
sub-operations for optimized writes. Both of these sub-operations
write to a shared distributed processor structure called the
'processor store buffer'. As a result, an unprivileged attacker could
use this flaw to read private data resident within the CPU's processor
store buffer. (CVE-2018-12126)

The virConnectGetDomainCapabilities() libvirt API accepts an
'emulatorbin' argument to specify the program providing emulation for
a domain. Since v1.2.19, libvirt will execute that program to probe
the domain's capabilities. Read-only clients could specify an
arbitrary path for this argument, causing libvirtd to execute a
crafted executable with its own privileges. (CVE-2019-10167)

It was discovered that libvirtd would permit readonly clients to use
the virDomainManagedSaveDefineXML() API, which would permit them to
modify managed save state files. If a managed save had already been
created by a privileged user, a local attacker could modify this file
such that libvirtd would execute an arbitrary program when the domain
was resumed. (CVE-2019-10166)

A vulnerability was found in libvirt >= 4.1.0 in the
virtlockd-admin.socket and virtlogd-admin.socket systemd units. A
missing SocketMode configuration parameter allows any user on the host
to connect using virtlockd-admin-sock or virtlogd-admin-sock and
perform administrative tasks against the virtlockd and virtlogd
daemons.(CVE-2019-10132)

The virConnectBaselineHypervisorCPU() and
virConnectCompareHypervisorCPU() libvirt APIs accept an 'emulator'
argument to specify the program providing emulation for a domain.
Since v1.2.19, libvirt will execute that program to probe the domain's
capabilities. Read-only clients could specify an arbitrary path for
this argument, causing libvirtd to execute a crafted executable with
its own privileges. (CVE-2019-10168)

It was discovered that libvirtd would permit read-only clients to use
the virDomainSaveImageGetXMLDesc() API, specifying an arbitrary path
which would be accessed with the permissions of the libvirtd process.
An attacker with access to the libvirtd socket could use this to probe
the existence of arbitrary files, cause denial of service or cause
libvirtd to execute arbitrary programs. (CVE-2019-10161)

Microprocessors use a load port subcomponent to perform load
operations from memory or IO. During a load operation, the load port
receives data from the memory or IO subsystem and then provides the
data to the CPU registers and operations in the CPUs pipelines. Stale
load operations results are stored in the 'load port' table until
overwritten by newer operations. Certain load-port operations
triggered by an attacker can be used to reveal data about previous
stale requests leaking data back to the attacker via a timing
side-channel. (CVE-2018-12127)

A flaw was found in the implementation of the 'fill buffer', a
mechanism used by modern CPUs when a cache-miss is made on L1 CPU
cache. If an attacker can generate a load operation that would create
a page fault, the execution will continue speculatively with incorrect
data from the fill buffer while the data is fetched from higher level
caches. This response time can be measured to infer data in the fill
buffer. (CVE-2018-12130)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://alas.aws.amazon.com/AL2/ALAS-2019-1274.html"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Run 'yum update libvirt' to update your system."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-10161");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libvirt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libvirt-admin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libvirt-bash-completion");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libvirt-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libvirt-daemon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libvirt-daemon-config-network");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libvirt-daemon-config-nwfilter");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libvirt-daemon-driver-interface");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libvirt-daemon-driver-lxc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libvirt-daemon-driver-network");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libvirt-daemon-driver-nodedev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libvirt-daemon-driver-nwfilter");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libvirt-daemon-driver-qemu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libvirt-daemon-driver-secret");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libvirt-daemon-driver-storage");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libvirt-daemon-driver-storage-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libvirt-daemon-driver-storage-disk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libvirt-daemon-driver-storage-gluster");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libvirt-daemon-driver-storage-iscsi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libvirt-daemon-driver-storage-logical");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libvirt-daemon-driver-storage-mpath");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libvirt-daemon-driver-storage-rbd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libvirt-daemon-driver-storage-scsi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libvirt-daemon-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libvirt-daemon-lxc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libvirt-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libvirt-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libvirt-docs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libvirt-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libvirt-lock-sanlock");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libvirt-login-shell");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libvirt-nss");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux:2");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/05/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/08/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/08/28");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2019-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"Amazon Linux Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/AmazonLinux/release", "Host/AmazonLinux/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

release = get_kb_item("Host/AmazonLinux/release");
if (isnull(release) || !strlen(release)) audit(AUDIT_OS_NOT, "Amazon Linux");
os_ver = pregmatch(pattern: "^AL(A|\d)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Amazon Linux");
os_ver = os_ver[1];
if (os_ver != "2")
{
  if (os_ver == 'A') os_ver = 'AMI';
  audit(AUDIT_OS_NOT, "Amazon Linux 2", "Amazon Linux " + os_ver);
}

if (!get_kb_item("Host/AmazonLinux/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


flag = 0;
if (rpm_check(release:"AL2", reference:"libvirt-4.5.0-10.amzn2.12.1")) flag++;
if (rpm_check(release:"AL2", reference:"libvirt-admin-4.5.0-10.amzn2.12.1")) flag++;
if (rpm_check(release:"AL2", reference:"libvirt-bash-completion-4.5.0-10.amzn2.12.1")) flag++;
if (rpm_check(release:"AL2", reference:"libvirt-client-4.5.0-10.amzn2.12.1")) flag++;
if (rpm_check(release:"AL2", reference:"libvirt-daemon-4.5.0-10.amzn2.12.1")) flag++;
if (rpm_check(release:"AL2", reference:"libvirt-daemon-config-network-4.5.0-10.amzn2.12.1")) flag++;
if (rpm_check(release:"AL2", reference:"libvirt-daemon-config-nwfilter-4.5.0-10.amzn2.12.1")) flag++;
if (rpm_check(release:"AL2", reference:"libvirt-daemon-driver-interface-4.5.0-10.amzn2.12.1")) flag++;
if (rpm_check(release:"AL2", reference:"libvirt-daemon-driver-lxc-4.5.0-10.amzn2.12.1")) flag++;
if (rpm_check(release:"AL2", reference:"libvirt-daemon-driver-network-4.5.0-10.amzn2.12.1")) flag++;
if (rpm_check(release:"AL2", reference:"libvirt-daemon-driver-nodedev-4.5.0-10.amzn2.12.1")) flag++;
if (rpm_check(release:"AL2", reference:"libvirt-daemon-driver-nwfilter-4.5.0-10.amzn2.12.1")) flag++;
if (rpm_check(release:"AL2", cpu:"x86_64", reference:"libvirt-daemon-driver-qemu-4.5.0-10.amzn2.12.1")) flag++;
if (rpm_check(release:"AL2", reference:"libvirt-daemon-driver-secret-4.5.0-10.amzn2.12.1")) flag++;
if (rpm_check(release:"AL2", reference:"libvirt-daemon-driver-storage-4.5.0-10.amzn2.12.1")) flag++;
if (rpm_check(release:"AL2", reference:"libvirt-daemon-driver-storage-core-4.5.0-10.amzn2.12.1")) flag++;
if (rpm_check(release:"AL2", reference:"libvirt-daemon-driver-storage-disk-4.5.0-10.amzn2.12.1")) flag++;
if (rpm_check(release:"AL2", cpu:"x86_64", reference:"libvirt-daemon-driver-storage-gluster-4.5.0-10.amzn2.12.1")) flag++;
if (rpm_check(release:"AL2", reference:"libvirt-daemon-driver-storage-iscsi-4.5.0-10.amzn2.12.1")) flag++;
if (rpm_check(release:"AL2", reference:"libvirt-daemon-driver-storage-logical-4.5.0-10.amzn2.12.1")) flag++;
if (rpm_check(release:"AL2", reference:"libvirt-daemon-driver-storage-mpath-4.5.0-10.amzn2.12.1")) flag++;
if (rpm_check(release:"AL2", cpu:"x86_64", reference:"libvirt-daemon-driver-storage-rbd-4.5.0-10.amzn2.12.1")) flag++;
if (rpm_check(release:"AL2", reference:"libvirt-daemon-driver-storage-scsi-4.5.0-10.amzn2.12.1")) flag++;
if (rpm_check(release:"AL2", cpu:"x86_64", reference:"libvirt-daemon-kvm-4.5.0-10.amzn2.12.1")) flag++;
if (rpm_check(release:"AL2", reference:"libvirt-daemon-lxc-4.5.0-10.amzn2.12.1")) flag++;
if (rpm_check(release:"AL2", reference:"libvirt-debuginfo-4.5.0-10.amzn2.12.1")) flag++;
if (rpm_check(release:"AL2", reference:"libvirt-devel-4.5.0-10.amzn2.12.1")) flag++;
if (rpm_check(release:"AL2", reference:"libvirt-docs-4.5.0-10.amzn2.12.1")) flag++;
if (rpm_check(release:"AL2", reference:"libvirt-libs-4.5.0-10.amzn2.12.1")) flag++;
if (rpm_check(release:"AL2", cpu:"x86_64", reference:"libvirt-lock-sanlock-4.5.0-10.amzn2.12.1")) flag++;
if (rpm_check(release:"AL2", reference:"libvirt-login-shell-4.5.0-10.amzn2.12.1")) flag++;
if (rpm_check(release:"AL2", reference:"libvirt-nss-4.5.0-10.amzn2.12.1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libvirt / libvirt-admin / libvirt-bash-completion / libvirt-client / etc");
}
