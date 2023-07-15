#%NASL_MIN_LEVEL 999999

#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2018:0169 and 
# Oracle Linux Security Advisory ELSA-2018-0169 respectively.
#
# @DEPRECATED@
#
# Disabled on 2018/01/31. There is no replacement.


if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(106367);
  script_version("3.4");
  script_cvs_date("Date: 2019/04/05 23:25:06");

  script_cve_id("CVE-2017-11176", "CVE-2017-7542", "CVE-2017-9074");
  script_xref(name:"RHSA", value:"2018:0169");

  script_name(english:"Oracle Linux 6 : kernel (ELSA-2018-0169) (deprecated)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"This plugin has been deprecated."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"From Red Hat Security Advisory 2018:0169 :

An update for kernel is now available for Red Hat Enterprise Linux 6.

Red Hat Product Security has rated this update as having a security
impact of Important. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available for each
vulnerability from the CVE link(s) in the References section.

The kernel packages contain the Linux kernel, the core of any Linux
operating system.

Security Fix(es) :

* An integer overflow vulnerability in ip6_find_1stfragopt() function
was found. A local attacker that has privileges (of CAP_NET_RAW) to
open raw socket can cause an infinite loop inside the
ip6_find_1stfragopt() function. (CVE-2017-7542, Moderate)

* The IPv6 fragmentation implementation in the Linux kernel does not
consider that the nexthdr field may be associated with an invalid
option, which allows local users to cause a denial of service
(out-of-bounds read and BUG) or possibly have unspecified other impact
via crafted socket and send system calls. Due to the nature of the
flaw, privilege escalation cannot be fully ruled out, although we
believe it is unlikely. (CVE-2017-9074, Moderate)

* A use-after-free flaw was found in the Netlink functionality of the
Linux kernel networking subsystem. Due to the insufficient cleanup in
the mq_notify function, a local attacker could potentially use this
flaw to escalate their privileges on the system. (CVE-2017-11176,
Moderate)

Bug Fix(es) :

* Previously, the default timeout and retry settings in the VMBus
driver were insufficient in some cases, for example when a Hyper-V
host was under a significant load. Consequently, in Windows Server
2016, Hyper-V Server 2016, and Windows Azure Platform, when running a
Red Hat Enterprise Linux Guest on the Hyper-V hypervisor, the guest
failed to boot or booted with certain Hyper-V devices missing. This
update alters the timeout and retry settings in VMBus, and Red Hat
Enterprise Linux guests now boot as expected under the described
conditions. (BZ#1506145)

* Previously, an incorrect external declaration in the be2iscsi driver
caused a kernel panic when using the systool utility. With this
update, the external declaration in be2iscsi has been fixed, and the
kernel no longer panics when using systool. (BZ#1507512)

* Under high usage of the NFSD file system and memory pressure, if
many tasks in the Linux kernel attempted to obtain the global spinlock
to clean the Duplicate Reply Cache (DRC), these tasks stayed in an
active wait in the nfsd_reply_cache_shrink() function for up to 99% of
time. Consequently, a high load average occurred. This update fixes
the bug by separating the DRC in several parts, each with an
independent spinlock. As a result, the load and CPU utilization is no
longer excessive under the described circumstances. (BZ#1509876)

* When attempting to attach multiple SCSI devices simultaneously, Red
Hat Enterprise Linux 6.9 on IBM z Systems sometimes became
unresponsive. This update fixes the zfcp device driver, and attaching
multiple SCSI devices simultaneously now works as expected in the
described scenario. (BZ# 1512425)

* On IBM z Systems, the tiqdio_call_inq_handlers() function in the
Linux kernel incorrectly cleared the device state change indicator
(DSCI) for the af_iucv devices using the HiperSockets transport with
multiple input queues. Consequently, queue stalls on such devices
occasionally occurred. With this update, tiqdio_call_inq_handlers()
has been fixed to clear the DSCI only once, prior to scanning the
queues. As a result, queue stalls for af_iucv devices using the
HiperSockets transport no longer occur under the described
circumstances. (BZ#1513314)

* Previously, small data chunks caused the Stream Control Transmission
Protocol (SCTP) to account the receiver_window (rwnd) values
incorrectly when recovering from a 'zero-window situation'. As a
consequence, window updates were not sent to the peer, and an
artificial growth of rwnd could lead to packet drops. This update
properly accounts such small data chunks and ignores the rwnd pressure
values when reopening a window. As a result, window updates are now
sent, and the announced rwnd reflects better the real state of the
receive buffer. (BZ#1514443)

This plugin has been deprecated because Oracle has changed their mind
and decided that ELSA-2018-0169 does not fix any security problems." 
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2018-January/007509.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"n/a"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-abi-whitelists");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-debug-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-firmware");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:perf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python-perf");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:6");

  script_set_attribute(attribute:"patch_publication_date", value:"2018/01/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/01/26");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2018-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"Oracle Linux Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/OracleLinux", "Host/RedHat/release", "Host/RedHat/rpm-list");

  exit(0);
}

exit(0, "This plugin has been deprecated.");

include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/OracleLinux")) audit(AUDIT_OS_NOT, "Oracle Linux");
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || !eregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux)", string:release)) audit(AUDIT_OS_NOT, "Oracle Linux");
os_ver = eregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux) .*release ([0-9]+(\.[0-9]+)?)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Oracle Linux");
os_ver = os_ver[1];
if (! ereg(pattern:"^6([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Oracle Linux 6", "Oracle Linux " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Oracle Linux", cpu);

flag = 0;
if (rpm_exists(release:"EL6", rpm:"kernel-2.6.32") && rpm_check(release:"EL6", reference:"kernel-2.6.32-696.20.1.el6")) flag++;
if (rpm_exists(release:"EL6", rpm:"kernel-abi-whitelists-2.6.32") && rpm_check(release:"EL6", reference:"kernel-abi-whitelists-2.6.32-696.20.1.el6")) flag++;
if (rpm_exists(release:"EL6", rpm:"kernel-debug-2.6.32") && rpm_check(release:"EL6", reference:"kernel-debug-2.6.32-696.20.1.el6")) flag++;
if (rpm_exists(release:"EL6", rpm:"kernel-debug-devel-2.6.32") && rpm_check(release:"EL6", reference:"kernel-debug-devel-2.6.32-696.20.1.el6")) flag++;
if (rpm_exists(release:"EL6", rpm:"kernel-devel-2.6.32") && rpm_check(release:"EL6", reference:"kernel-devel-2.6.32-696.20.1.el6")) flag++;
if (rpm_exists(release:"EL6", rpm:"kernel-doc-2.6.32") && rpm_check(release:"EL6", reference:"kernel-doc-2.6.32-696.20.1.el6")) flag++;
if (rpm_exists(release:"EL6", rpm:"kernel-firmware-2.6.32") && rpm_check(release:"EL6", reference:"kernel-firmware-2.6.32-696.20.1.el6")) flag++;
if (rpm_exists(release:"EL6", rpm:"kernel-headers-2.6.32") && rpm_check(release:"EL6", reference:"kernel-headers-2.6.32-696.20.1.el6")) flag++;
if (rpm_check(release:"EL6", reference:"perf-2.6.32-696.20.1.el6")) flag++;
if (rpm_check(release:"EL6", reference:"python-perf-2.6.32-696.20.1.el6")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "affected kernel");
}
