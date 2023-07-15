#
# (C) Tenable Network Security, Inc.
#
# The package checks in this plugin were extracted from OracleVM
# Security Advisory OVMSA-2018-0238.
#

include("compat.inc");

if (description)
{
  script_id(111023);
  script_version("1.8");
  script_cvs_date("Date: 2019/09/27 13:00:35");

  script_cve_id("CVE-2016-9603", "CVE-2017-13672", "CVE-2017-15289", "CVE-2017-2633", "CVE-2017-5715", "CVE-2017-7718", "CVE-2017-7980", "CVE-2018-3639", "CVE-2018-5683", "CVE-2018-7858");

  script_name(english:"OracleVM 3.4 : qemu-kvm (OVMSA-2018-0238) (Spectre)");
  script_summary(english:"Checks the RPM output for the updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote OracleVM host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The remote OracleVM system is missing necessary patches to address
critical security updates :

  -
    qemu-kvm-i386-define-the-ssbd-CPUID-feature-bit-CVE-2018
    -3639.patch 

  -
    qemu-kvm-i386-Define-the-Virt-SSBD-MSR-and-handling-of-i
    t-CVE.patch 

  -
    qemu-kvm-i386-define-the-AMD-virt-ssbd-CPUID-feature-bit
    -CVE-.patch 

  - Resolves: bz#1574074 (CVE-2018-3639 qemu-kvm: hw: cpu:
    speculative store bypass [rhel-6.10.z])

  - kvm-vga-add-share_surface-flag.patch [bz#1553674]

  - kvm-vga-add-sanity-checks.patch [bz#1553674]

  - Resolves: bz#1553674 (CVE-2018-7858 qemu-kvm: Qemu:
    cirrus: OOB access when updating vga display [rhel-6])

  - kvm-target-i386-add-support-for-SPEC_CTRL-MSR.patch
    [bz#1525939 bz#1528024]

  -
    kvm-target-i386-cpu-add-new-CPUID-bits-for-indirect-bran
    .patch 

  -
    kvm-target-i386-cpu-add-new-CPU-models-for-indirect-bran
    .patch 

  -
    kvm-cirrus-fix-oob-access-in-mode4and5-write-functions.p
    atch [bz#1501298]

  -
    kvm-vga-stop-passing-pointers-to-vga_draw_line-functions
    .patch 

  -
    kvm-vga-check-the-validation-of-memory-addr-when-draw-te
    .patch 

  - Resolves: bz#1486641 (CVE-2017-13672 qemu-kvm-rhev:
    Qemu: vga: OOB read access during display update
    [rhel-6.10])

  - Resolves: bz#1501298 (CVE-2017-15289 qemu-kvm: Qemu:
    cirrus: OOB access issue in mode4and5 write functions
    [rhel-6.10])

  - Resolves: bz#1525939 (CVE-2017-5715 qemu-kvm: hw: cpu:
    speculative execution branch target injection
    [rhel-6.10])

  - Resolves: bz#1528024 (CVE-2017-5715 qemu-kvm-rhev: hw:
    cpu: speculative execution branch target injection
    [rhel-6.10])

  - Resolves: bz#1534692 (CVE-2018-5683 qemu-kvm: Qemu:
    Out-of-bounds read in vga_draw_text routine [rhel-6.10])

  - Resolves: bz#1549152 (qemu-kvm-rhev: remove unused patch
    file [rhel-6.10])

  - kvm-vns-tls-don-t-use-depricated-gnutls-functions.patch
    [bz#1428750]

  - kvm-vnc-apply-display-size-limits.patch [bz#1430616
    bz#1430617]

  -
    kvm-fix-cirrus_vga-fix-OOB-read-case-qemu-Segmentation-f
    .patch 

  -
    kvm-cirrus-vnc-zap-bitblit-support-from-console-code.pat
    ch [bz#1443448 bz#1443450 bz#1447542 bz#1447545]

  - kvm-cirrus-avoid-write-only-variables.patch [bz#1444378
    bz#1444380]

  -
    kvm-cirrus-stop-passing-around-dst-pointers-in-the-blitt
    .patch 

  -
    kvm-cirrus-stop-passing-around-src-pointers-in-the-blitt
    .patch 

  -
    kvm-cirrus-fix-off-by-one-in-cirrus_bitblt_rop_bkwd_tran
    .patch 

  - kvm-cirrus-fix-PUTPIXEL-macro.patch [bz#1444378
    bz#1444380]

  - Resolves: bz#1428750 (Fails to build in brew)

  - Resolves: bz#1430616 (CVE-2017-2633 qemu-kvm: Qemu: VNC:
    memory corruption due to unchecked resolution limit
    [rhel-6.10])

  - Resolves: bz#1430617 (CVE-2017-2633 qemu-kvm-rhev: Qemu:
    VNC: memory corruption due to unchecked resolution limit
    [rhel-6.10])

  - Resolves: bz#1443448 (CVE-2017-7718 qemu-kvm: Qemu:
    display: cirrus: OOB read access issue [rhel-6.10])

  - Resolves: bz#1443450 (CVE-2017-7718 qemu-kvm-rhev: Qemu:
    display: cirrus: OOB read access issue [rhel-6.10])

  - Resolves: bz#1444378 (CVE-2017-7980 qemu-kvm: Qemu:
    display: cirrus: OOB r/w access issues in bitblt
    routines [rhel-6.10])

  - Resolves: bz#1444380 (CVE-2017-7980 qemu-kvm-rhev: Qemu:
    display: cirrus: OOB r/w access issues in bitblt
    routines [rhel-6.10])

  - Resolves: bz#1447542 (CVE-2016-9603 qemu-kvm: Qemu:
    cirrus: heap buffer overflow via vnc connection
    [rhel-6.10])

  - Resolves: bz#1447545 (CVE-2016-9603 qemu-kvm-rhev: Qemu:
    cirrus: heap buffer overflow via vnc connection
    [rhel-6.10])"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/oraclevm-errata/2018-July/000873.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected qemu-img package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:vm:qemu-img");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:vm_server:3.4");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/04/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/07/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/07/12");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2018-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (rpm_check(release:"OVS3.4", reference:"qemu-img-0.12.1.2-2.506.el6_10.1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "qemu-img");
}
