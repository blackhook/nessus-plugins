#
# (C) Tenable Network Security, Inc.
#
# The package checks in this plugin were extracted from OracleVM
# Security Advisory OVMSA-2018-0254.
#

include("compat.inc");

if (description)
{
  script_id(117377);
  script_version("1.3");
  script_cvs_date("Date: 2019/09/27 13:00:35");

  script_cve_id("CVE-2018-14678", "CVE-2018-3620", "CVE-2018-3646");

  script_name(english:"OracleVM 3.4 : Unbreakable / etc (OVMSA-2018-0254) (Foreshadow)");
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

Oracle VM Security Advisory OVMSA-2018-0254

The following updated rpms for Oracle VM 3.4 have been uploaded to the
Unbreakable Linux Network :

x86_64: kernel-uek-4.1.12-124.19.1.el6uek.x86_64.rpm
kernel-uek-firmware-4.1.12-124.19.1.el6uek.noarch.rpm

SRPMS :

Description of changes :

  - x86/entry/64: Ensure %ebx handling correct in
    xen_failsafe_callback (George Kennedy) [Orabug:
    28402927] (CVE-2018-14678)

  - x86/speculation/l1tf: Increase l1tf memory limit for
    Nehalem+ (Andi Kleen) [Orabug: 28488808] (CVE-2018-3620)

  - x86/speculation/l1tf: Suggest what to do on systems with
    too much RAM (Vlastimil Babka) [Orabug: 28488808]
    (CVE-2018-3620)

  - x86/speculation/l1tf: Fix off-by-one error when warning
    that system has too much RAM (Vlastimil Babka) [Orabug:
    28488808] (CVE-2018-3620)

  - x86/speculation/l1tf: Fix overflow in l1tf_pfn_limit on
    32bit (Vlastimil Babka) [Orabug: 28488808]
    (CVE-2018-3620)

  - x86/speculation/l1tf: Exempt zeroed PTEs from inversion
    (Sean Christopherson) [Orabug: 28488808] (CVE-2018-3620)

  - x86/l1tf: Fix build error seen if CONFIG_KVM_INTEL is
    disabled (Guenter Roeck) [Orabug: 28488808]
    (CVE-2018-3620)

  - x86/spectre: Add missing family 6 check to microcode
    check (Andi Kleen) [Orabug: 28488808] (CVE-2018-3620)

  - KVM: x86: SVM: Call x86_spec_ctrl_set_guest/host with
    interrupts disabled (Thomas Gleixner) [Orabug: 28488808]
    (CVE-2018-3646)

  - x86/microcode: Allow late microcode loading with SMT
    disabled (Josh Poimboeuf) [Orabug: 28488808]
    (CVE-2018-3620)

  - x86/microcode: Do not upload microcode if CPUs are
    offline (Ashok Raj) [Orabug: 28488808] (CVE-2018-3620)"
  );
  # https://oss.oracle.com/pipermail/oraclevm-errata/2018-September/000889.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?a2499664"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected kernel-uek / kernel-uek-firmware packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:vm:kernel-uek");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:vm:kernel-uek-firmware");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:vm_server:3.4");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/07/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/09/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/09/10");
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
if (rpm_check(release:"OVS3.4", reference:"kernel-uek-4.1.12-124.19.1.el6uek")) flag++;
if (rpm_check(release:"OVS3.4", reference:"kernel-uek-firmware-4.1.12-124.19.1.el6uek")) flag++;

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
