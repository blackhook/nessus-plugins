#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2020:1016 and 
# CentOS Errata and Security Advisory 2020:1016 respectively.
#

include('compat.inc');

if (description)
{
  script_id(135316);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/13");

  script_cve_id(
    "CVE-2015-9289",
    "CVE-2017-17807",
    "CVE-2018-7191",
    "CVE-2018-19985",
    "CVE-2018-20169",
    "CVE-2019-3901",
    "CVE-2019-9503",
    "CVE-2019-10207",
    "CVE-2019-10638",
    "CVE-2019-10639",
    "CVE-2019-11190",
    "CVE-2019-11884",
    "CVE-2019-12382",
    "CVE-2019-13233",
    "CVE-2019-13648",
    "CVE-2019-14283",
    "CVE-2019-15916",
    "CVE-2019-16746",
    "CVE-2019-18660"
  );
  script_xref(name:"RHSA", value:"2020:1016");

  script_name(english:"CentOS 7 : kernel (CESA-2020:1016)");

  script_set_attribute(attribute:"synopsis", value:
"The remote CentOS host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Redhat Enterprise Linux 7 host has packages installed that are affected by multiple vulnerabilities as
referenced in the RHSA-2020:1016 advisory.

  - kernel: out of bound read in DVB connexant driver.
    (CVE-2015-9289)

  - kernel: Missing permissions check for request_key()
    destination allows local attackers to add keys to
    keyring without Write permission (CVE-2017-17807)

  - kernel: oob memory read in hso_probe in
    drivers/net/usb/hso.c (CVE-2018-19985)

  - kernel: usb: missing size check in the
    __usb_get_extra_descriptor() leading to DoS
    (CVE-2018-20169)

  - kernel: denial of service via ioctl call in network tun
    handling (CVE-2018-7191)

  - kernel: null-pointer dereference in
    hci_uart_set_flow_control (CVE-2019-10207)

  - Kernel: net: weak IP ID generation leads to remote
    device tracking (CVE-2019-10638)

  - Kernel: net: using kernel space address bits to derive
    IP ID may potentially break KASLR (CVE-2019-10639)

  - kernel: ASLR bypass for setuid binaries due to late
    install_exec_creds() (CVE-2019-11190)

  - kernel: sensitive information disclosure from kernel
    stack memory via HIDPCONNADD command (CVE-2019-11884)

  - kernel: unchecked kstrdup of fwstr in
    drm_load_edid_firmware leads to denial of service
    (CVE-2019-12382)

  - kernel: use-after-free in arch/x86/lib/insn-eval.c
    (CVE-2019-13233)

  - kernel: denial of service in
    arch/powerpc/kernel/signal_32.c and
    arch/powerpc/kernel/signal_64.c via sigreturn() system
    call (CVE-2019-13648)

  - kernel: integer overflow and OOB read in
    drivers/block/floppy.c (CVE-2019-14283)

  - kernel: memory leak in register_queue_kobjects() in
    net/core/net-sysfs.c leads to denial of service
    (CVE-2019-15916)

  - kernel: buffer-overflow hardening in WiFi beacon
    validation code. (CVE-2019-16746)

  - kernel: (powerpc) incomplete Spectre-RSB mitigation
    leads to information exposure (CVE-2019-18660)

  - kernel: perf_event_open() and execve() race in setuid
    programs allows a data leak (CVE-2019-3901)

  - kernel: brcmfmac frame validation bypass (CVE-2019-9503)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://lists.centos.org/pipermail/centos-cr-announce/2020-April/012401.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?05ca73ea");
  script_set_attribute(attribute:"solution", value:
"Update the affected kernel packages.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-9503");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2019-16746");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/12/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/04/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/04/10");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:bpftool");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-abi-whitelists");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-debug-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-tools-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-tools-libs-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:perf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:python-perf");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:7");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CentOS Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2020-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"bpftool-3.10.0-1127.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"kernel-3.10.0-1127.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"kernel-abi-whitelists-3.10.0-1127.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"kernel-debug-3.10.0-1127.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"kernel-debug-devel-3.10.0-1127.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"kernel-devel-3.10.0-1127.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"kernel-doc-3.10.0-1127.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"kernel-headers-3.10.0-1127.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"kernel-tools-3.10.0-1127.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"kernel-tools-libs-3.10.0-1127.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"kernel-tools-libs-devel-3.10.0-1127.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"perf-3.10.0-1127.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"python-perf-3.10.0-1127.el7")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "bpftool / kernel / kernel-abi-whitelists / kernel-debug / etc");
}
