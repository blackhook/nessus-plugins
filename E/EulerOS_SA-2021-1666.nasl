#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(147678);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/10");

  script_cve_id(
    "CVE-2020-12430",
    "CVE-2020-14301",
    "CVE-2020-14339",
    "CVE-2020-25637"
  );

  script_name(english:"EulerOS Virtualization 2.9.0 : libvirt (EulerOS-SA-2021-1666)");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS Virtualization host is missing multiple security
updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the libvirt packages installed, the
EulerOS Virtualization installation on the remote host is affected by
the following vulnerabilities :

  - A double free memory issue was found to occur in the
    libvirt API, in versions before 6.8.0, responsible for
    requesting information about network interfaces of a
    running QEMU domain. This flaw affects the polkit
    access control driver. Specifically, clients connecting
    to the read-write socket with limited ACL permissions
    could use this flaw to crash the libvirt daemon,
    resulting in a denial of service, or potentially
    escalate their privileges on the system. The highest
    threat from this vulnerability is to data
    confidentiality and integrity as well as system
    availability.(CVE-2020-25637)

  - A flaw was found in libvirt, where it leaked a file
    descriptor for `/dev/mapper/control` into the QEMU
    process. This file descriptor allows for privileged
    operations to happen against the device-mapper on the
    host. This flaw allows a malicious guest user or
    process to perform operations outside of their standard
    permissions, potentially causing serious damage to the
    host operating system. The highest threat from this
    vulnerability is to confidentiality, integrity, as well
    as system availability.(CVE-2020-14339)

  - An issue was discovered in qemuDomainGetStatsIOThread
    in qemu/qemu_driver.c in libvirt 4.10.0 though 6.x
    before 6.1.0. A memory leak was found in the
    virDomainListGetStats libvirt API that is responsible
    for retrieving domain statistics when managing QEMU
    guests. This flaw allows unprivileged users with a
    read-only connection to cause a memory leak in the
    domstats command, resulting in a potential denial of
    service.(CVE-2020-12430)

  - An information disclosure vulnerability was found in
    libvirt. HTTP cookies used to access network-based
    disks were saved in the XML dump of the guest domain.
    This flaw allows an attacker to access potentially
    sensitive information in the domain configuration via
    the `dumpxml` command.(CVE-2020-14301)

Note that Tenable Network Security has extracted the preceding
description block directly from the EulerOS security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2021-1666
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?5bb1743c");
  script_set_attribute(attribute:"solution", value:
"Update the affected libvirt packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-25637");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2020-14339");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"patch_publication_date", value:"2021/03/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/03/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:libvirt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:libvirt-admin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:libvirt-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:libvirt-daemon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:libvirt-daemon-config-network");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:libvirt-daemon-config-nwfilter");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:libvirt-daemon-driver-interface");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:libvirt-daemon-driver-network");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:libvirt-daemon-driver-nodedev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:libvirt-daemon-driver-nwfilter");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:libvirt-daemon-driver-qemu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:libvirt-daemon-driver-secret");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:libvirt-daemon-driver-storage");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:libvirt-daemon-driver-storage-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:libvirt-daemon-driver-storage-disk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:libvirt-daemon-driver-storage-iscsi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:libvirt-daemon-driver-storage-logical");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:libvirt-daemon-driver-storage-mpath");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:libvirt-daemon-driver-storage-scsi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:libvirt-daemon-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:libvirt-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:libvirt-docs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:libvirt-libs");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:huawei:euleros:uvp:2.9.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Huawei Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/EulerOS/release", "Host/EulerOS/rpm-list", "Host/EulerOS/uvp_version");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

release = get_kb_item("Host/EulerOS/release");
if (isnull(release) || release !~ "^EulerOS") audit(AUDIT_OS_NOT, "EulerOS");
uvp = get_kb_item("Host/EulerOS/uvp_version");
if (uvp != "2.9.0") audit(AUDIT_OS_NOT, "EulerOS Virtualization 2.9.0");
if (!get_kb_item("Host/EulerOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "aarch64" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "EulerOS", cpu);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_ARCH_NOT, "i686 / x86_64", cpu);

flag = 0;

pkgs = ["libvirt-6.2.0-2.9.1.2.197",
        "libvirt-admin-6.2.0-2.9.1.2.197",
        "libvirt-client-6.2.0-2.9.1.2.197",
        "libvirt-daemon-6.2.0-2.9.1.2.197",
        "libvirt-daemon-config-network-6.2.0-2.9.1.2.197",
        "libvirt-daemon-config-nwfilter-6.2.0-2.9.1.2.197",
        "libvirt-daemon-driver-interface-6.2.0-2.9.1.2.197",
        "libvirt-daemon-driver-network-6.2.0-2.9.1.2.197",
        "libvirt-daemon-driver-nodedev-6.2.0-2.9.1.2.197",
        "libvirt-daemon-driver-nwfilter-6.2.0-2.9.1.2.197",
        "libvirt-daemon-driver-qemu-6.2.0-2.9.1.2.197",
        "libvirt-daemon-driver-secret-6.2.0-2.9.1.2.197",
        "libvirt-daemon-driver-storage-6.2.0-2.9.1.2.197",
        "libvirt-daemon-driver-storage-core-6.2.0-2.9.1.2.197",
        "libvirt-daemon-driver-storage-disk-6.2.0-2.9.1.2.197",
        "libvirt-daemon-driver-storage-iscsi-6.2.0-2.9.1.2.197",
        "libvirt-daemon-driver-storage-logical-6.2.0-2.9.1.2.197",
        "libvirt-daemon-driver-storage-mpath-6.2.0-2.9.1.2.197",
        "libvirt-daemon-driver-storage-scsi-6.2.0-2.9.1.2.197",
        "libvirt-daemon-kvm-6.2.0-2.9.1.2.197",
        "libvirt-devel-6.2.0-2.9.1.2.197",
        "libvirt-docs-6.2.0-2.9.1.2.197",
        "libvirt-libs-6.2.0-2.9.1.2.197"];

foreach (pkg in pkgs)
  if (rpm_check(release:"EulerOS-2.0", reference:pkg)) flag++;

if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_HOLE,
    extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libvirt");
}
