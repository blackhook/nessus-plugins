#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(109449);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/02/24");

  script_cve_id("CVE-2016-3672", "CVE-2016-7913", "CVE-2016-8633", "CVE-2017-1000252", "CVE-2017-1000407", "CVE-2017-1000410", "CVE-2017-12154", "CVE-2017-12190", "CVE-2017-13166", "CVE-2017-14140", "CVE-2017-15116", "CVE-2017-15121", "CVE-2017-15126", "CVE-2017-15127", "CVE-2017-15129", "CVE-2017-15265", "CVE-2017-17448", "CVE-2017-17449", "CVE-2017-17558", "CVE-2017-18017", "CVE-2017-18203", "CVE-2017-5754", "CVE-2017-7294", "CVE-2017-8824", "CVE-2017-9725", "CVE-2018-1000004", "CVE-2018-5750", "CVE-2018-6927");
  script_xref(name:"IAVA", value:"2018-A-0019");

  script_name(english:"Scientific Linux Security Update : kernel on SL7.x x86_64 (20180410) (Meltdown)");
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

  - hw: cpu: speculative execution permission faults
    handling (CVE-2017-5754, Important, KVM for Power)

  - kernel: Buffer overflow in firewire driver via crafted
    incoming packets (CVE-2016-8633, Important)

  - kernel: Use-after-free vulnerability in DCCP socket
    (CVE-2017-8824, Important)

  - Kernel: kvm: nVMX: L2 guest could access hardware(L0)
    CR8 register (CVE-2017-12154, Important)

  - kernel: v4l2: disabled memory access protection
    mechanism allowing privilege escalation (CVE-2017-13166,
    Important)

  - kernel: media: use-after-free in [tuner-xc2028] media
    driver (CVE-2016-7913, Moderate)

  - kernel: drm/vmwgfx: fix integer overflow in
    vmw_surface_define_ioctl() (CVE-2017-7294, Moderate)

  - kernel: Incorrect type conversion for size during dma
    allocation (CVE-2017-9725, Moderate)

  - kernel: memory leak when merging buffers in SCSI IO
    vectors (CVE-2017-12190, Moderate)

  - kernel: vfs: BUG in truncate_inode_pages_range() and
    fuse client (CVE-2017-15121, Moderate)

  - kernel: Use-after-free in
    userfaultfd_event_wait_completion function in
    userfaultfd.c (CVE-2017-15126, Moderate)

  - kernel: net: double-free and memory corruption in
    get_net_ns_by_id() (CVE-2017-15129, Moderate)

  - kernel: Use-after-free in snd_seq_ioctl_create_port()
    (CVE-2017-15265, Moderate)

  - kernel: Missing capabilities check in
    net/netfilter/nfnetlink_cthelper.c allows for
    unprivileged access to systemwide nfnl_cthelper_list
    structure (CVE-2017-17448, Moderate)

  - kernel: Missing namespace check in
    net/netlink/af_netlink.c allows for network monitors to
    observe systemwide activity (CVE-2017-17449, Moderate)

  - kernel: Unallocated memory access by malicious USB
    device via bNumInterfaces overflow (CVE-2017-17558,
    Moderate)

  - kernel: netfilter: use-after-free in
    tcpmss_mangle_packet function in
    net/netfilter/xt_TCPMSS.c (CVE-2017-18017, Moderate)

  - kernel: Race condition in
    drivers/md/dm.c:dm_get_from_kobject() allows local users
    to cause a denial of service (CVE-2017-18203, Moderate)

  - kernel: kvm: Reachable BUG() on out-of-bounds guest IRQ
    (CVE-2017-1000252, Moderate)

  - Kernel: KVM: DoS via write flood to I/O port 0x80
    (CVE-2017-1000407, Moderate)

  - kernel: Stack information leak in the EFS element
    (CVE-2017-1000410, Moderate)

  - kernel: Kernel address information leak in
    drivers/acpi/sbshc.c:acpi_smbus_hc_add() function
    potentially allowing KASLR bypass (CVE-2018-5750,
    Moderate)

  - kernel: Race condition in sound system can lead to
    denial of service (CVE-2018-1000004, Moderate)

  - kernel: multiple Low security impact security issues
    (CVE-2016-3672, CVE-2017-14140, CVE-2017-15116,
    CVE-2017-15127, CVE-2018-6927, Low)

Additional Changes :"
  );
  # https://listserv.fnal.gov/scripts/wa.exe?A2=ind1804&L=scientific-linux-errata&F=&S=&P=5119
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?21bff66d"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
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

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/04/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/04/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/05/01");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2018-2020 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"kernel-3.10.0-862.el7")) flag++;
if (rpm_check(release:"SL7", reference:"kernel-abi-whitelists-3.10.0-862.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"kernel-debug-3.10.0-862.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"kernel-debug-debuginfo-3.10.0-862.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"kernel-debug-devel-3.10.0-862.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"kernel-debuginfo-3.10.0-862.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"kernel-debuginfo-common-x86_64-3.10.0-862.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"kernel-devel-3.10.0-862.el7")) flag++;
if (rpm_check(release:"SL7", reference:"kernel-doc-3.10.0-862.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"kernel-headers-3.10.0-862.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"kernel-tools-3.10.0-862.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"kernel-tools-debuginfo-3.10.0-862.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"kernel-tools-libs-3.10.0-862.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"kernel-tools-libs-devel-3.10.0-862.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"perf-3.10.0-862.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"perf-debuginfo-3.10.0-862.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"python-perf-3.10.0-862.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"python-perf-debuginfo-3.10.0-862.el7")) flag++;


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
