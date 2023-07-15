#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include('deprecated_nasl_level.inc');
include("compat.inc");

if (description)
{
  script_id(106369);
  script_version("3.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/03/30");

  script_cve_id("CVE-2017-11176", "CVE-2017-7542", "CVE-2017-9074");

  script_name(english:"Scientific Linux Security Update : kernel on SL6.x i386/x86_64 (20180125)");
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

  - An integer overflow vulnerability in
    ip6_find_1stfragopt() function was found. A local
    attacker that has privileges (of CAP_NET_RAW) to open
    raw socket can cause an infinite loop inside the
    ip6_find_1stfragopt() function. (CVE-2017-7542,
    Moderate)

  - The IPv6 fragmentation implementation in the Linux
    kernel does not consider that the nexthdr field may be
    associated with an invalid option, which allows local
    users to cause a denial of service (out-of-bounds read
    and BUG) or possibly have unspecified other impact via
    crafted socket and send system calls. Due to the nature
    of the flaw, privilege escalation cannot be fully ruled
    out, although we believe it is unlikely. (CVE-2017-9074,
    Moderate)

  - A use-after-free flaw was found in the Netlink
    functionality of the Linux kernel networking subsystem.
    Due to the insufficient cleanup in the mq_notify
    function, a local attacker could potentially use this
    flaw to escalate their privileges on the system.
    (CVE-2017-11176, Moderate)

Bug Fix(es) :

  - Previously, the default timeout and retry settings in
    the VMBus driver were insufficient in some cases, for
    example when a Hyper-V host was under a significant
    load. Consequently, in Windows Server 2016, Hyper-V
    Server 2016, and Windows Azure Platform, when running a
    Scientific Linux Guest on the Hyper-V hypervisor, the
    guest failed to boot or booted with certain Hyper-V
    devices missing. This update alters the timeout and
    retry settings in VMBus, and Scientific Linux guests now
    boot as expected under the described conditions.

  - Previously, an incorrect external declaration in the
    be2iscsi driver caused a kernel panic when using the
    systool utility. With this update, the external
    declaration in be2iscsi has been fixed, and the kernel
    no longer panics when using systool.

  - Under high usage of the NFSD file system and memory
    pressure, if many tasks in the Linux kernel attempted to
    obtain the global spinlock to clean the Duplicate Reply
    Cache (DRC), these tasks stayed in an active wait in the
    nfsd_reply_cache_shrink() function for up to 99% of
    time. Consequently, a high load average occurred. This
    update fixes the bug by separating the DRC in several
    parts, each with an independent spinlock. As a result,
    the load and CPU utilization is no longer excessive
    under the described circumstances.

  - When attempting to attach multiple SCSI devices
    simultaneously, Scientific Linux 6.9 on IBM z Systems
    sometimes became unresponsive. This update fixes the
    zfcp device driver, and attaching multiple SCSI devices
    simultaneously now works as expected in the described
    scenario.

  - On IBM z Systems, the tiqdio_call_inq_handlers()
    function in the Linux kernel incorrectly cleared the
    device state change indicator (DSCI) for the af_iucv
    devices using the HiperSockets transport with multiple
    input queues. Consequently, queue stalls on such devices
    occasionally occurred. With this update,
    tiqdio_call_inq_handlers() has been fixed to clear the
    DSCI only once, prior to scanning the queues. As a
    result, queue stalls for af_iucv devices using the
    HiperSockets transport no longer occur under the
    described circumstances.

  - Previously, small data chunks caused the Stream Control
    Transmission Protocol (SCTP) to account the
    receiver_window (rwnd) values incorrectly when
    recovering from a 'zero-window situation'. As a
    consequence, window updates were not sent to the peer,
    and an artificial growth of rwnd could lead to packet
    drops. This update properly accounts such small data
    chunks and ignores the rwnd pressure values when
    reopening a window. As a result, window updates are now
    sent, and the announced rwnd reflects better the real
    state of the receive buffer."
  );
  # https://listserv.fnal.gov/scripts/wa.exe?A2=ind1801&L=scientific-linux-errata&F=&S=&P=9818
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?26a008af"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:kernel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:kernel-abi-whitelists");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:kernel-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:kernel-debug-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:kernel-debug-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:kernel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:kernel-debuginfo-common-i686");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:kernel-debuginfo-common-x86_64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:kernel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:kernel-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:kernel-firmware");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:kernel-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:perf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:perf-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:python-perf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:python-perf-debuginfo");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/05/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/01/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/01/26");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2018-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (! preg(pattern:"^6([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Scientific Linux 6.x", "Scientific Linux " + os_ver);
if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu >!< "x86_64" && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Scientific Linux", cpu);


flag = 0;
if (rpm_check(release:"SL6", reference:"kernel-2.6.32-696.20.1.el6")) flag++;
if (rpm_check(release:"SL6", reference:"kernel-abi-whitelists-2.6.32-696.20.1.el6")) flag++;
if (rpm_check(release:"SL6", reference:"kernel-debug-2.6.32-696.20.1.el6")) flag++;
if (rpm_check(release:"SL6", reference:"kernel-debug-debuginfo-2.6.32-696.20.1.el6")) flag++;
if (rpm_check(release:"SL6", reference:"kernel-debug-devel-2.6.32-696.20.1.el6")) flag++;
if (rpm_check(release:"SL6", reference:"kernel-debuginfo-2.6.32-696.20.1.el6")) flag++;
if (rpm_check(release:"SL6", reference:"kernel-debuginfo-common-i686-2.6.32-696.20.1.el6")) flag++;
if (rpm_check(release:"SL6", cpu:"x86_64", reference:"kernel-debuginfo-common-x86_64-2.6.32-696.20.1.el6")) flag++;
if (rpm_check(release:"SL6", reference:"kernel-devel-2.6.32-696.20.1.el6")) flag++;
if (rpm_check(release:"SL6", reference:"kernel-doc-2.6.32-696.20.1.el6")) flag++;
if (rpm_check(release:"SL6", reference:"kernel-firmware-2.6.32-696.20.1.el6")) flag++;
if (rpm_check(release:"SL6", reference:"kernel-headers-2.6.32-696.20.1.el6")) flag++;
if (rpm_check(release:"SL6", reference:"perf-2.6.32-696.20.1.el6")) flag++;
if (rpm_check(release:"SL6", reference:"perf-debuginfo-2.6.32-696.20.1.el6")) flag++;
if (rpm_check(release:"SL6", reference:"python-perf-2.6.32-696.20.1.el6")) flag++;
if (rpm_check(release:"SL6", reference:"python-perf-debuginfo-2.6.32-696.20.1.el6")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "kernel / kernel-abi-whitelists / kernel-debug / etc");
}
