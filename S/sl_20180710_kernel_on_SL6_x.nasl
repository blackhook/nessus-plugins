#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(111002);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/02/24");

  script_cve_id("CVE-2018-10675", "CVE-2018-10872", "CVE-2018-3639", "CVE-2018-3665", "CVE-2018-8897");

  script_name(english:"Scientific Linux Security Update : kernel on SL6.x i386/x86_64 (20180710) (Spectre)");
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

  - An industry-wide issue was found in the way many modern
    microprocessor designs have implemented speculative
    execution of Load &amp; Store instructions (a commonly
    used performance optimization). It relies on the
    presence of a precisely-defined instruction sequence in
    the privileged code as well as the fact that memory read
    from address to which a recent memory write has occurred
    may see an older value and subsequently cause an update
    into the microprocessor's data cache even for
    speculatively executed instructions that never actually
    commit (retire). As a result, an unprivileged attacker
    could use this flaw to read privileged memory by
    conducting targeted cache side-channel attacks.
    (CVE-2018-3639, x86 AMD)

  - kernel: Use-after-free vulnerability in
    mm/mempolicy.c:do_get_mempolicy function allows local
    denial of service or other unspecified impact
    (CVE-2018-10675)

  - Kernel: FPU state information leakage via lazy FPU
    restore (CVE-2018-3665)

  - kernel: error in exception handling leads to DoS
    (CVE-2018-8897 regression) (CVE-2018-10872)

Bug Fix(es) :

  - Previously, microcode updates on 32 and 64-bit AMD and
    Intel architectures were not synchronized. As a
    consequence, it was not possible to apply the microcode
    updates. This fix adds the synchronization to the
    microcode updates so that processors of the stated
    architectures receive updates at the same time. As a
    result, microcode updates are now synchronized."
  );
  # https://listserv.fnal.gov/scripts/wa.exe?A2=ind1807&L=scientific-linux-errata&F=&S=&P=5892
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?d22d741a"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Microsoft Windows POP/MOV SS Local Privilege Elevation Vulnerability');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

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

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/05/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/07/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/07/11");
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
if (rpm_check(release:"SL6", reference:"kernel-2.6.32-754.2.1.el6")) flag++;
if (rpm_check(release:"SL6", reference:"kernel-abi-whitelists-2.6.32-754.2.1.el6")) flag++;
if (rpm_check(release:"SL6", reference:"kernel-debug-2.6.32-754.2.1.el6")) flag++;
if (rpm_check(release:"SL6", reference:"kernel-debug-debuginfo-2.6.32-754.2.1.el6")) flag++;
if (rpm_check(release:"SL6", reference:"kernel-debug-devel-2.6.32-754.2.1.el6")) flag++;
if (rpm_check(release:"SL6", reference:"kernel-debuginfo-2.6.32-754.2.1.el6")) flag++;
if (rpm_check(release:"SL6", reference:"kernel-debuginfo-common-i686-2.6.32-754.2.1.el6")) flag++;
if (rpm_check(release:"SL6", cpu:"x86_64", reference:"kernel-debuginfo-common-x86_64-2.6.32-754.2.1.el6")) flag++;
if (rpm_check(release:"SL6", reference:"kernel-devel-2.6.32-754.2.1.el6")) flag++;
if (rpm_check(release:"SL6", reference:"kernel-doc-2.6.32-754.2.1.el6")) flag++;
if (rpm_check(release:"SL6", reference:"kernel-firmware-2.6.32-754.2.1.el6")) flag++;
if (rpm_check(release:"SL6", reference:"kernel-headers-2.6.32-754.2.1.el6")) flag++;
if (rpm_check(release:"SL6", reference:"perf-2.6.32-754.2.1.el6")) flag++;
if (rpm_check(release:"SL6", reference:"perf-debuginfo-2.6.32-754.2.1.el6")) flag++;
if (rpm_check(release:"SL6", reference:"python-perf-2.6.32-754.2.1.el6")) flag++;
if (rpm_check(release:"SL6", reference:"python-perf-debuginfo-2.6.32-754.2.1.el6")) flag++;


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
