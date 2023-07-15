#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(130078);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/18");

  script_cve_id("CVE-2018-20856", "CVE-2019-10126", "CVE-2019-3846", "CVE-2019-9506");

  script_name(english:"Scientific Linux Security Update : kernel on SL7.x x86_64 (20191016)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote Scientific Linux host is missing one or more security
updates."
  );
  script_set_attribute(
    attribute:"description",
    value:
"Security Fix(es) :

  - kernel: Use-after-free in __blk_drain_queue() function
    in block/blk-core.c (CVE-2018-20856)

  - kernel: Heap overflow in mwifiex_update_bss_desc_with_ie
    function in marvell/mwifiex/scan.c (CVE-2019-3846)

  - hardware: bluetooth: BR/EDR encryption key negotiation
    attacks (KNOB) (CVE-2019-9506)

  - kernel: Heap overflow in mwifiex_uap_parse_tail_ies
    function in drivers/net/wireless/marvell/mwifiex/ie.c
    (CVE-2019-10126)

For more details about the security issue(s), including the impact, a
CVSS score, acknowledgments, and other related information, refer to
the CVE page(s) listed in the References section.

Bug Fixes :

  - gfs2: Fix iomap write page reclaim deadlock (BZ#1737373)

  - [FJ7.6 Bug]: [REG] kernel: ipc: ipc_free should use
    kvfree (BZ#1740178)

  - high update_cfs_rq_blocked_load contention (BZ#1740180)

  - [Hyper-V][RHEL 7] kdump fails to start on a Hyper-V
    guest of Windows Server 2019. (BZ#1740188)

  - kvm: backport cpuidle-haltpoll driver (BZ#1740192)

  - Growing unreclaimable slab memory (BZ#1741920)

  - [bnx2x] ping failed from pf to vf which has been
    attached to vm (BZ#1741926)

  - [Hyper-V]vPCI devices cannot allocate IRQs vectors in a
    Hyper-V VM with > 240 vCPUs (i.e., when in x2APIC mode)
    (BZ#1743324)

  - Macsec: inbound MACSEC frame is unexpectedly dropped
    with InPktsNotValid (BZ#1744442)

  - RHEL 7.7 Beta - Hit error when trying to run nvme
    connect with IPv6 address (BZ#1744443)

  - RHEL 7.6 SS4 - Paths lost when running straight I/O on
    NVMe/RoCE system (BZ#1744444)

  - NFSv4.0 client sending a double CLOSE (leading to EIO
    application failure) (BZ#1744946)

  - [Azure] CRI-RDOS | [RHEL 7.8] Live migration only takes
    10 seconds, but the VM was unavailable for 2 hours
    (BZ#1748239)

  - NFS client autodisconnect timer may fire immediately
    after TCP connection setup and may cause DoS type
    reconnect problem in complex network environments
    (BZ#1749290)

  - [Inspur] RHEL7.6 ASPEED graphic card display issue
    (BZ#1749296)

  - Allows macvlan to operated correctly over the
    active-backup mode to support bonding events.
    (BZ#1751579)

  - [LLNL 7.5 Bug] slab leak causing a crash when using kmem
    control group (BZ#1752421)

Users of kernel are advised to upgrade to these updated packages,
which fix these bugs."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=1737373"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=1740178"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=1740180"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=1740188"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=1740192"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=1741920"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=1741926"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=1743324"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=1744442"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=1744443"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=1744444"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=1744946"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=1748239"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=1749290"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=1749296"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=1751579"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=1752421"
  );
  # https://listserv.fnal.gov/scripts/wa.exe?A2=ind1910&L=SCIENTIFIC-LINUX-ERRATA&P=1567
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?3e7582ac"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-3846");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:bpftool");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:bpftool-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:kernel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:kernel-abi-whitelists");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:kernel-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:kernel-debug-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:kernel-debug-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:kernel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:kernel-debuginfo-common-x86_64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:kernel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:kernel-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:kernel-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:kernel-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:kernel-tools-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:kernel-tools-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:kernel-tools-libs-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:perf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:perf-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:python-perf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:python-perf-debuginfo");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/06/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/10/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/10/21");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2019-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"Scientific Linux Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/RedHat/release", "Host/RedHat/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || "Scientific Linux " >!< release) audit(AUDIT_HOST_NOT, "running Scientific Linux");
os_ver = pregmatch(pattern: "Scientific Linux.*release ([0-9]+(\.[0-9]+)?)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Scientific Linux");
os_ver = os_ver[1];
if (! preg(pattern:"^7([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Scientific Linux 7.x", "Scientific Linux " + os_ver);
if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu >!< "x86_64" && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Scientific Linux", cpu);


flag = 0;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"bpftool-3.10.0-1062.4.1.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"bpftool-debuginfo-3.10.0-1062.4.1.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"kernel-3.10.0-1062.4.1.el7")) flag++;
if (rpm_check(release:"SL7", reference:"kernel-abi-whitelists-3.10.0-1062.4.1.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"kernel-debug-3.10.0-1062.4.1.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"kernel-debug-debuginfo-3.10.0-1062.4.1.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"kernel-debug-devel-3.10.0-1062.4.1.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"kernel-debuginfo-3.10.0-1062.4.1.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"kernel-debuginfo-common-x86_64-3.10.0-1062.4.1.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"kernel-devel-3.10.0-1062.4.1.el7")) flag++;
if (rpm_check(release:"SL7", reference:"kernel-doc-3.10.0-1062.4.1.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"kernel-headers-3.10.0-1062.4.1.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"kernel-tools-3.10.0-1062.4.1.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"kernel-tools-debuginfo-3.10.0-1062.4.1.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"kernel-tools-libs-3.10.0-1062.4.1.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"kernel-tools-libs-devel-3.10.0-1062.4.1.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"perf-3.10.0-1062.4.1.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"perf-debuginfo-3.10.0-1062.4.1.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"python-perf-3.10.0-1062.4.1.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"python-perf-debuginfo-3.10.0-1062.4.1.el7")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "bpftool / bpftool-debuginfo / kernel / kernel-abi-whitelists / etc");
}
