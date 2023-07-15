#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(140959);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/12");

  script_cve_id(
    "CVE-2020-0404",
    "CVE-2020-14385",
    "CVE-2020-14390",
    "CVE-2020-16166",
    "CVE-2020-24394",
    "CVE-2020-25212",
    "CVE-2020-25284"
  );

  script_name(english:"EulerOS Virtualization for ARM 64 3.0.6.0 : kernel (EulerOS-SA-2020-2011)");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS Virtualization for ARM 64 host is missing multiple security
updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the kernel packages installed, the
EulerOS Virtualization for ARM 64 installation on the remote host is
affected by the following vulnerabilities :

  - The Linux kernel through 5.7.11 allows remote attackers
    to make observations that help to obtain sensitive
    information about the internal state of the network
    RNG, aka CID-f227e3ec3b5c. This is related to
    drivers/char/random.c and
    kernel/time/timer.c.(CVE-2020-16166)

  - In the Linux kernel before 5.7.8, fs/nfsd/vfs.c (in the
    NFS server) can set incorrect permissions on new
    filesystem objects when the filesystem lacks ACL
    support, aka CID-22cf8419f131. This occurs because the
    current umask is not considered.(CVE-2020-24394)

  - In uvc_scan_chain_forward of uvc_driver.c, there is a
    possible linked list corruption due to an unusual root
    cause. This could lead to local escalation of privilege
    in the kernel with no additional execution privileges
    needed. User interaction is not needed for
    exploitation.Product: AndroidVersions: Android
    kernelAndroid ID: A-111893654References: Upstream
    kernel(CVE-2020-0404)

  - A TOCTOU mismatch in the NFS client code in the Linux
    kernel before 5.8.3 could be used by local attackers to
    corrupt memory or possibly have unspecified other
    impact because a size check is in fs/nfs/nfs4proc.c
    instead of fs/nfs/nfs4xdr.c, aka
    CID-b4487b935452.(CVE-2020-25212)

  - A flaw was found in the Linux kernel before 5.9-rc4. A
    failure of the file system metadata validator in XFS
    can cause an inode with a valid, user-creatable
    extended attribute to be flagged as corrupt. This can
    lead to the filesystem being shutdown, or otherwise
    rendered inaccessible until it is remounted, leading to
    a denial of service. The highest threat from this
    vulnerability is to system
    availability.(CVE-2020-14385)

  - The rbd block device driver in drivers/block/rbd.c in
    the Linux kernel through 5.8.9 used incomplete
    permission checking for access to rbd devices, which
    could be leveraged by local attackers to map or unmap
    rbd block devices, aka
    CID-f44d04e696fe.(CVE-2020-25284)

  - A flaw was found in the Linux kernel in versions from
    2.2.3 through 5.9.rc5. When changing screen size, an
    out-of-bounds memory write can occur leading to memory
    corruption or a denial of service. This highest threat
    from this vulnerability is to system
    availability.(CVE-2020-14390)

Note that Tenable Network Security has extracted the preceding
description block directly from the EulerOS security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2020-2011
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?82243a9c");
  script_set_attribute(attribute:"solution", value:
"Update the affected kernel packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-14390");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2020-24394");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"patch_publication_date", value:"2020/09/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/09/29");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel-tools-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel-tools-libs-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:perf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:python-perf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:python3-perf");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:huawei:euleros:uvp:3.0.6.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Huawei Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2020-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (uvp != "3.0.6.0") audit(AUDIT_OS_NOT, "EulerOS Virtualization 3.0.6.0");
if (!get_kb_item("Host/EulerOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "aarch64" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "EulerOS", cpu);
if ("aarch64" >!< cpu) audit(AUDIT_ARCH_NOT, "aarch64", cpu);

flag = 0;

pkgs = ["kernel-4.19.36-vhulk1907.1.0.h839.eulerosv2r8",
        "kernel-devel-4.19.36-vhulk1907.1.0.h839.eulerosv2r8",
        "kernel-headers-4.19.36-vhulk1907.1.0.h839.eulerosv2r8",
        "kernel-tools-4.19.36-vhulk1907.1.0.h839.eulerosv2r8",
        "kernel-tools-libs-4.19.36-vhulk1907.1.0.h839.eulerosv2r8",
        "kernel-tools-libs-devel-4.19.36-vhulk1907.1.0.h839.eulerosv2r8",
        "perf-4.19.36-vhulk1907.1.0.h839.eulerosv2r8",
        "python-perf-4.19.36-vhulk1907.1.0.h839.eulerosv2r8",
        "python3-perf-4.19.36-vhulk1907.1.0.h839.eulerosv2r8"];

foreach (pkg in pkgs)
  if (rpm_check(release:"EulerOS-2.0", reference:pkg)) flag++;

if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_WARNING,
    extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "kernel");
}
