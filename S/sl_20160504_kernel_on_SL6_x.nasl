#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(90939);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2015-5157", "CVE-2015-8767");

  script_name(english:"Scientific Linux Security Update : kernel on SL6.x i386/x86_64 (20160504)");
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

  - A flaw was found in the way the Linux kernel handled
    IRET faults during the processing of NMIs. An
    unprivileged, local user could use this flaw to crash
    the system or, potentially (although highly unlikely),
    escalate their privileges on the system. (CVE-2015-5157,
    Moderate)

  - A race condition flaw was found in the way the Linux
    kernel's SCTP implementation handled sctp_accept()
    during the processing of heartbeat timeout events. A
    remote attacker could use this flaw to prevent further
    connections to be accepted by the SCTP server running on
    the system, resulting in a denial of service.
    (CVE-2015-8767, Moderate)

Bug Fix(es) :

  - When the nvme driver held the queue lock for too long,
    for example during DMA mapping, a lockup occurred
    leading to nvme hard-lockup panic. This update fixes the
    underlying source code, and nvme now works as expected.

  - Due to a regression, a Unix domain datagram socket could
    come to a deadlock when sending a datagram to itself.
    The provided patch adds another 'sk' check to the
    unix_dgram_sendmsg() function, and the aforementioned
    deadlock no longer occurs.

  - Previously, writing a large file using direct I/O in 16
    MB chunks sometimes caused a pathological allocation
    pattern where 16 MB chunks of large free extent were
    allocated to a file in reversed order. The provided
    patch avoids the backward allocation, and writing a
    large file using direct I/O now proceeds successfully.

  - MD RAID1 devices that repeatedly became hot removed and
    re-added could become mismatched due to a race
    condition. This caused them to return stale data,
    leading to data corruption. The provided set of patches
    fixes this bug, and hot removals and re-additions of md
    devices now work as expected.

  - A couple of previous fixes caused a deadlock on the 'rq'
    lock leading to a kernel panic on CPU 0. The provided
    set of patches reverts the relevant commits, thus
    preventing the panic from occurring.

Enhancement(s) :

  - VLAN support has been updated to integrate some of the
    latest upstream features. This update also makes sure
    that NULL pointer crashes related to VLAN support in
    bonding mode no longer occur and that tag stripping and
    insertion work as expected.

  - This update adds additional model numbers for Broadwell
    to perf."
  );
  # https://listserv.fnal.gov/scripts/wa.exe?A2=ind1605&L=scientific-linux-errata&F=&S=&P=417
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?d2aea0bf"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");

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

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/08/31");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/05/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/05/06");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (rpm_check(release:"SL6", reference:"kernel-2.6.32-573.26.1.el6")) flag++;
if (rpm_check(release:"SL6", reference:"kernel-abi-whitelists-2.6.32-573.26.1.el6")) flag++;
if (rpm_check(release:"SL6", reference:"kernel-debug-2.6.32-573.26.1.el6")) flag++;
if (rpm_check(release:"SL6", reference:"kernel-debug-debuginfo-2.6.32-573.26.1.el6")) flag++;
if (rpm_check(release:"SL6", reference:"kernel-debug-devel-2.6.32-573.26.1.el6")) flag++;
if (rpm_check(release:"SL6", reference:"kernel-debuginfo-2.6.32-573.26.1.el6")) flag++;
if (rpm_check(release:"SL6", reference:"kernel-debuginfo-common-i686-2.6.32-573.26.1.el6")) flag++;
if (rpm_check(release:"SL6", cpu:"x86_64", reference:"kernel-debuginfo-common-x86_64-2.6.32-573.26.1.el6")) flag++;
if (rpm_check(release:"SL6", reference:"kernel-devel-2.6.32-573.26.1.el6")) flag++;
if (rpm_check(release:"SL6", reference:"kernel-doc-2.6.32-573.26.1.el6")) flag++;
if (rpm_check(release:"SL6", reference:"kernel-firmware-2.6.32-573.26.1.el6")) flag++;
if (rpm_check(release:"SL6", reference:"kernel-headers-2.6.32-573.26.1.el6")) flag++;
if (rpm_check(release:"SL6", reference:"perf-2.6.32-573.26.1.el6")) flag++;
if (rpm_check(release:"SL6", reference:"perf-debuginfo-2.6.32-573.26.1.el6")) flag++;
if (rpm_check(release:"SL6", reference:"python-perf-2.6.32-573.26.1.el6")) flag++;
if (rpm_check(release:"SL6", reference:"python-perf-debuginfo-2.6.32-573.26.1.el6")) flag++;


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
