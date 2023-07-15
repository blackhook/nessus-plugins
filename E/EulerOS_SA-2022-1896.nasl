##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(162355);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/06/17");

  script_cve_id(
    "CVE-2021-4203",
    "CVE-2021-45868",
    "CVE-2022-0494",
    "CVE-2022-1011",
    "CVE-2022-1016",
    "CVE-2022-1353",
    "CVE-2022-28388",
    "CVE-2022-28390"
  );

  script_name(english:"EulerOS 2.0 SP5 : kernel (EulerOS-SA-2022-1896)");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS host is missing multiple security updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the kernel packages installed, the EulerOS installation on the remote host is affected by
the following vulnerabilities :

  - A use-after-free read flaw was found in sock_getsockopt() in net/core/sock.c due to SO_PEERCRED and
    SO_PEERGROUPS race with listen() (and connect()) in the Linux kernel. In this flaw, an attacker with a
    user privileges may crash the system or leak internal kernel information. (CVE-2021-4203)

  - In the Linux kernel before 5.15.3, fs/quota/quota_tree.c does not validate the block number in the quota
    tree (on disk). This can, for example, lead to a kernel/locking/rwsem.c use-after-free if there is a
    corrupted quota file. (CVE-2021-45868)

  - A kernel information leak flaw was identified in the scsi_ioctl function in drivers/scsi/scsi_ioctl.c in
    the Linux kernel. This flaw allows a local attacker with a special user privilege (CAP_SYS_ADMIN or
    CAP_SYS_RAWIO) to create issues with confidentiality. (CVE-2022-0494)

  - A use-after-free flaw was found in the Linux kernel's FUSE filesystem in the way a user triggers write().
    This flaw allows a local user to gain unauthorized access to data from the FUSE filesystem, resulting in
    privilege escalation. (CVE-2022-1011)

  - A vulnerability was found in the pfkey_register function in net/key/af_key.c in the Linux kernel. This
    flaw allows a local, unprivileged user to gain access to kernel memory, leading to a system crash or a
    leak of internal kernel information. (CVE-2022-1353)

  - usb_8dev_start_xmit in drivers/net/can/usb/usb_8dev.c in the Linux kernel through 5.17.1 has a double
    free. (CVE-2022-28388)

  - ems_usb_start_xmit in drivers/net/can/usb/ems_usb.c in the Linux kernel through 5.17.1 has a double free.
    (CVE-2022-28390)

Note that Tenable Network Security has extracted the preceding description block directly from the EulerOS security
advisory. Tenable has attempted to automatically clean and format it as much as possible without introducing additional
issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2022-1896
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?7de3df93");
  script_set_attribute(attribute:"solution", value:
"Update the affected kernel packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-0494");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2022-28390");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/03/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/06/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/06/17");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel-tools-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:perf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:python-perf");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:huawei:euleros:2.0");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Huawei Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/EulerOS/release", "Host/EulerOS/rpm-list", "Host/EulerOS/sp");
  script_exclude_keys("Host/EulerOS/uvp_version");

  exit(0);
}

include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

var release = get_kb_item("Host/EulerOS/release");
if (isnull(release) || release !~ "^EulerOS") audit(AUDIT_OS_NOT, "EulerOS");
var uvp = get_kb_item("Host/EulerOS/uvp_version");
if (release !~ "^EulerOS release 2\.0(\D|$)") audit(AUDIT_OS_NOT, "EulerOS 2.0 SP5");

var sp = get_kb_item("Host/EulerOS/sp");
if (isnull(sp) || sp !~ "^(5)$") audit(AUDIT_OS_NOT, "EulerOS 2.0 SP5");

if (!empty_or_null(uvp)) audit(AUDIT_OS_NOT, "EulerOS 2.0 SP5", "EulerOS UVP " + uvp);

if (!get_kb_item("Host/EulerOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "aarch64" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "EulerOS", cpu);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_ARCH_NOT, "i686 / x86_64", cpu);

var flag = 0;

var pkgs = [
  "kernel-3.10.0-862.14.1.5.h687.eulerosv2r7",
  "kernel-devel-3.10.0-862.14.1.5.h687.eulerosv2r7",
  "kernel-headers-3.10.0-862.14.1.5.h687.eulerosv2r7",
  "kernel-tools-3.10.0-862.14.1.5.h687.eulerosv2r7",
  "kernel-tools-libs-3.10.0-862.14.1.5.h687.eulerosv2r7",
  "perf-3.10.0-862.14.1.5.h687.eulerosv2r7",
  "python-perf-3.10.0-862.14.1.5.h687.eulerosv2r7"
];

foreach (var pkg in pkgs)
  if (rpm_check(release:"EulerOS-2.0", sp:"5", reference:pkg)) flag++;

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
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "kernel");
}
