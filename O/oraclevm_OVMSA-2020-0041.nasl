#
# (C) Tenable Network Security, Inc.
#
# The package checks in this plugin were extracted from OracleVM
# Security Advisory OVMSA-2020-0041.
#

include("compat.inc");

if (description)
{
  script_id(140361);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/13");

  script_cve_id("CVE-2017-16644", "CVE-2019-10638", "CVE-2019-10639", "CVE-2019-19049", "CVE-2019-19062", "CVE-2019-19535", "CVE-2019-20811", "CVE-2020-10732");

  script_name(english:"OracleVM 3.4 : Unbreakable / etc (OVMSA-2020-0041)");
  script_summary(english:"Checks the RPM output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote OracleVM host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The remote OracleVM system is missing necessary patches to address
critical security updates :

  - can: peak_usb: pcan_usb_fd: Fix info-leaks to USB
    devices (Tomas Bortoli) [Orabug: 31351221]
    (CVE-2019-19535)

  - media: hdpvr: Fix an error handling path in hdpvr_probe
    (Arvind Yadav) [Orabug: 31352053] (CVE-2017-16644)

  - fs/binfmt_misc.c: do not allow offset overflow (Thadeu
    Lima de Souza Cascardo) [Orabug: 31588258] - clear inode
    and truncate pages before enqueuing for async
    inactivation (Gautham Ananthakrishna) [Orabug: 31744270]

  - mm: create alloc_last_chance debugfs entries (Mike
    Kravetz) [Orabug: 31295499] - mm: perform 'last chance'
    reclaim efforts before allocation failure (Mike Kravetz)
    [Orabug: 31295499] - mm: let page allocation slowpath
    retry 'order' times (Mike Kravetz) [Orabug: 31295499] -
    fix kABI breakage from 'netns: provide pure entropy for
    net_hash_mix' (Dan Duval) [Orabug: 31351904]
    (CVE-2019-10638) (CVE-2019-10639)

  - netns: provide pure entropy for net_hash_mix (Eric
    Dumazet) [Orabug: 31351904] (CVE-2019-10638)
    (CVE-2019-10639)

  - hrtimer: Annotate lockless access to timer->base (Eric
    Dumazet) [Orabug: 31380495] - rds: ib: Revert 'net/rds:
    Avoid stalled connection due to CM REQ retries'
    (H&aring kon Bugge) [Orabug: 31648141] - rds: Clear
    reconnect pending bit (H&aring kon Bugge) [Orabug:
    31648141] - RDMA/netlink: Do not always generate an ACK
    for some netlink operations (H&aring kon Bugge) [Orabug:
    31666975] - genirq/proc: Return proper error code when
    irq_set_affinity fails (Wen Yaxng) [Orabug: 31723450]

  - fs/binfmt_elf.c: allocate initialized memory in
    fill_thread_core_info (Alexander Potapenko) [Orabug:
    31350639] (CVE-2020-10732)

  - crypto: user - fix memory leak in crypto_report (Navid
    Emamdoost) [Orabug: 31351640] (CVE-2019-19062)

  - of: unittest: fix memory leak in unittest_data_add
    (Navid Emamdoost) [Orabug: 31351702] (CVE-2019-19049)

  - IB/sa: Resolv use-after-free in ib_nl_make_request
    (Divya Indi) [Orabug: 31656992] - net-sysfs: call
    dev_hold if kobject_init_and_add success (YueHaibing)
    [Orabug: 31687545] (CVE-2019-20811)"
  );
  # https://oss.oracle.com/pipermail/oraclevm-errata/2020-September/000999.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?566c17a8"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Update the affected kernel-uek / kernel-uek-firmware packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-16644");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:vm:kernel-uek");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:vm:kernel-uek-firmware");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:vm_server:3.4");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/11/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/09/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/09/08");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2020-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"OracleVM Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/OracleVM/release", "Host/OracleVM/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/OracleVM/release");
if (isnull(release) || "OVS" >!< release) audit(AUDIT_OS_NOT, "OracleVM");
if (! preg(pattern:"^OVS" + "3\.4" + "(\.[0-9]|$)", string:release)) audit(AUDIT_OS_NOT, "OracleVM 3.4", "OracleVM " + release);
if (!get_kb_item("Host/OracleVM/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "OracleVM", cpu);
if ("x86_64" >!< cpu) audit(AUDIT_ARCH_NOT, "x86_64", cpu);

flag = 0;
if (rpm_check(release:"OVS3.4", reference:"kernel-uek-4.1.12-124.42.3.el6uek")) flag++;
if (rpm_check(release:"OVS3.4", reference:"kernel-uek-firmware-4.1.12-124.42.3.el6uek")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "kernel-uek / kernel-uek-firmware");
}
