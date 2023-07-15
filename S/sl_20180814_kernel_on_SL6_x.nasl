#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(111777);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/02/24");

  script_cve_id("CVE-2017-0861", "CVE-2017-15265", "CVE-2018-1000004", "CVE-2018-10901", "CVE-2018-3620", "CVE-2018-3646", "CVE-2018-3693", "CVE-2018-7566");

  script_name(english:"Scientific Linux Security Update : kernel on SL6.x i386/x86_64 (20180814) (Foreshadow)");
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

  - Modern operating systems implement virtualization of
    physical memory to efficiently use available system
    resources and provide inter-domain protection through
    access control and isolation. The L1TF issue was found
    in the way the x86 microprocessor designs have
    implemented speculative execution of instructions (a
    commonly used performance optimisation) in combination
    with handling of page-faults caused by terminated
    virtual to physical address resolving process. As a
    result, an unprivileged attacker could use this flaw to
    read privileged memory of the kernel or other processes
    and/or cross guest/host boundaries to read host memory
    by conducting targeted cache side-channel attacks.
    (CVE-2018-3620, CVE-2018-3646)

  - An industry-wide issue was found in the way many modern
    microprocessor designs have implemented speculative
    execution of instructions past bounds check. The flaw
    relies on the presence of a precisely-defined
    instruction sequence in the privileged code and the fact
    that memory writes occur to an address which depends on
    the untrusted value. Such writes cause an update into
    the microprocessor's data cache even for speculatively
    executed instructions that never actually commit
    (retire). As a result, an unprivileged attacker could
    use this flaw to influence speculative execution and/or
    read privileged memory by conducting targeted cache
    side- channel attacks. (CVE-2018-3693)

  - kernel: kvm: vmx: host GDT limit corruption
    (CVE-2018-10901)

  - kernel: Use-after-free in snd_pcm_info function in ALSA
    subsystem potentially leads to privilege escalation
    (CVE-2017-0861)

  - kernel: Use-after-free in snd_seq_ioctl_create_port()
    (CVE-2017-15265)

  - kernel: race condition in snd_seq_write() may lead to
    UAF or OOB-access (CVE-2018-7566)

  - kernel: Race condition in sound system can lead to
    denial of service (CVE-2018-1000004)

Bug Fix(es) :

  - The Least recently used (LRU) operations are batched by
    caching pages in per-cpu page vectors to prevent
    contention of the heavily used lru_lock spinlock. The
    page vectors can hold even the compound pages.
    Previously, the page vectors were cleared only if they
    were full. Subsequently, the amount of memory held in
    page vectors, which is not reclaimable, was sometimes
    too high. Consequently the page reclamation started the
    Out of Memory (OOM) killing processes. With this update,
    the underlying source code has been fixed to clear LRU
    page vectors each time when a compound page is added to
    them. As a result, OOM killing processes due to high
    amounts of memory held in page vectors no longer occur."
  );
  # https://listserv.fnal.gov/scripts/wa.exe?A2=ind1808&L=scientific-linux-errata&F=&S=&P=1270
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?d03c589b"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");

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

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/10/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/08/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/08/16");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_set_attribute(attribute:"generated_plugin", value:"current");
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
if (! preg(pattern:"^6([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Scientific Linux 6.x", "Scientific Linux " + os_ver);
if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu >!< "x86_64" && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Scientific Linux", cpu);


flag = 0;
if (rpm_check(release:"SL6", reference:"kernel-2.6.32-754.3.5.el6")) flag++;
if (rpm_check(release:"SL6", reference:"kernel-abi-whitelists-2.6.32-754.3.5.el6")) flag++;
if (rpm_check(release:"SL6", reference:"kernel-debug-2.6.32-754.3.5.el6")) flag++;
if (rpm_check(release:"SL6", reference:"kernel-debug-debuginfo-2.6.32-754.3.5.el6")) flag++;
if (rpm_check(release:"SL6", reference:"kernel-debug-devel-2.6.32-754.3.5.el6")) flag++;
if (rpm_check(release:"SL6", reference:"kernel-debuginfo-2.6.32-754.3.5.el6")) flag++;
if (rpm_check(release:"SL6", reference:"kernel-debuginfo-common-i686-2.6.32-754.3.5.el6")) flag++;
if (rpm_check(release:"SL6", cpu:"x86_64", reference:"kernel-debuginfo-common-x86_64-2.6.32-754.3.5.el6")) flag++;
if (rpm_check(release:"SL6", reference:"kernel-devel-2.6.32-754.3.5.el6")) flag++;
if (rpm_check(release:"SL6", reference:"kernel-doc-2.6.32-754.3.5.el6")) flag++;
if (rpm_check(release:"SL6", reference:"kernel-firmware-2.6.32-754.3.5.el6")) flag++;
if (rpm_check(release:"SL6", reference:"kernel-headers-2.6.32-754.3.5.el6")) flag++;
if (rpm_check(release:"SL6", reference:"perf-2.6.32-754.3.5.el6")) flag++;
if (rpm_check(release:"SL6", reference:"perf-debuginfo-2.6.32-754.3.5.el6")) flag++;
if (rpm_check(release:"SL6", reference:"python-perf-2.6.32-754.3.5.el6")) flag++;
if (rpm_check(release:"SL6", reference:"python-perf-debuginfo-2.6.32-754.3.5.el6")) flag++;


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
