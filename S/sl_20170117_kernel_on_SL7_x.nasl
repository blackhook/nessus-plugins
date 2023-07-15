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
  script_id(96599);
  script_version("3.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2016-6828", "CVE-2016-7117", "CVE-2016-9555");

  script_name(english:"Scientific Linux Security Update : kernel on SL7.x x86_64 (20170117)");
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
"To see the complete list of bug fixes, users are directed to the
related Knowledge Article :

Security Fix(es) :

  - A use-after-free vulnerability was found in the kernel's
    socket recvmmsg subsystem. This may allow remote
    attackers to corrupt memory and may allow execution of
    arbitrary code. This corruption takes place during the
    error handling routines within __sys_recvmmsg()
    function. (CVE-2016-7117, Important)

  - A use-after-free vulnerability was found in
    tcp_xmit_retransmit_queue and other tcp_* functions.
    This condition could allow an attacker to send an
    incorrect selective acknowledgment to existing
    connections, possibly resetting a connection.
    (CVE-2016-6828, Moderate)

  - A flaw was found in the Linux kernel's implementation of
    the SCTP protocol. A remote attacker could trigger an
    out-of-bounds read with an offset of up to 64kB
    potentially causing the system to crash. (CVE-2016-9555,
    Moderate)

Bug Fix(es) :

  - Previously, the performance of Internet Protocol over
    InfiniBand (IPoIB) was suboptimal due to a conflict of
    IPoIB with the Generic Receive Offload (GRO)
    infrastructure. With this update, the data cached by the
    IPoIB driver has been moved from a control block into
    the IPoIB hard header, thus avoiding the GRO problem and
    the corruption of IPoIB address information. As a
    result, the performance of IPoIB has been improved.

  - Previously, when a virtual machine (VM) with
    PCI-Passthrough interfaces was recreated, a race
    condition between the eventfd daemon and the virqfd
    daemon occurred. Consequently, the operating system
    rebooted. This update fixes the race condition. As a
    result, the operating system no longer reboots in the
    described situation.

  - Previously, a packet loss occurred when the team driver
    in round-robin mode was sending a large number of
    packets. This update fixes counting of the packets in
    the round-robin runner of the team driver, and the
    packet loss no longer occurs in the described situation.

  - Previously, the virtual network devices contained in the
    deleted namespace could be deleted in any order. If the
    loopback device was not deleted as the last item, other
    netns devices, such as vxlan devices, could end up with
    dangling references to the loopback device.
    Consequently, deleting a network namespace (netns)
    occasionally ended by a kernel oops. With this update,
    the underlying source code has been fixed to ensure the
    correct order when deleting the virtual network devices
    on netns deletion. As a result, the kernel oops no
    longer occurs under the described circumstances.

  - Previously, a Kabylake system with a Sunrise Point
    Platform Controller Hub (PCH) with a PCI device ID of
    0xA149 showed the following warning messages during the
    boot :

'Unknown Intel PCH (0xa149) detected.' 'Warning: Intel Kabylake
processor with unknown PCH - this hardware has not undergone testing
...'

The messages were shown because this PCH was not properly recognized.
With this update, the problem has been fixed, and the operating system
now boots without displaying the warning messages.

  - Previously, the operating system occasionally became
    unresponsive after a long run. This was caused by a race
    condition between the try_to_wake_up() function and a
    woken up task in the core scheduler. With this update,
    the race condition has been fixed, and the operating
    system no longer locks up in the described scenario."
  );
  # https://listserv.fnal.gov/scripts/wa.exe?A2=ind1701&L=scientific-linux-errata&F=&S=&P=9762
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?27df62d7"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
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

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/10/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/01/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/01/18");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"kernel-3.10.0-514.6.1.el7")) flag++;
if (rpm_check(release:"SL7", reference:"kernel-abi-whitelists-3.10.0-514.6.1.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"kernel-debug-3.10.0-514.6.1.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"kernel-debug-debuginfo-3.10.0-514.6.1.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"kernel-debug-devel-3.10.0-514.6.1.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"kernel-debuginfo-3.10.0-514.6.1.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"kernel-debuginfo-common-x86_64-3.10.0-514.6.1.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"kernel-devel-3.10.0-514.6.1.el7")) flag++;
if (rpm_check(release:"SL7", reference:"kernel-doc-3.10.0-514.6.1.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"kernel-headers-3.10.0-514.6.1.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"kernel-tools-3.10.0-514.6.1.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"kernel-tools-debuginfo-3.10.0-514.6.1.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"kernel-tools-libs-3.10.0-514.6.1.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"kernel-tools-libs-devel-3.10.0-514.6.1.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"perf-3.10.0-514.6.1.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"perf-debuginfo-3.10.0-514.6.1.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"python-perf-3.10.0-514.6.1.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"python-perf-debuginfo-3.10.0-514.6.1.el7")) flag++;


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
