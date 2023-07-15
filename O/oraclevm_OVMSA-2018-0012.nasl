#
# (C) Tenable Network Security, Inc.
#
# The package checks in this plugin were extracted from OracleVM
# Security Advisory OVMSA-2018-0012.
#

include("compat.inc");

if (description)
{
  script_id(106226);
  script_version("3.8");
  script_cvs_date("Date: 2019/09/27 13:00:35");

  script_cve_id("CVE-2017-1000407", "CVE-2017-5753");
  script_xref(name:"IAVA", value:"2018-A-0020");

  script_name(english:"OracleVM 3.4 : Unbreakable / etc (OVMSA-2018-0012) (Spectre)");
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

  - Revert 'kernel.spec: Require the new microcode_ctl.'
    (Brian Maly)

  - xen-blkback: add pending_req allocation stats (Ankur
    Arora) [Orabug: 27386890]

  - xen-blkback: move indirect req allocation out-of-line
    (Ankur Arora) 

  - xen-blkback: pull nseg validation out in a function
    (Ankur Arora) 

  - xen-blkback: make struct pending_req less monolithic
    (Ankur Arora) 

  - x86: Clean up IBRS functionality resident in common code
    (Kanth Ghatraju) [Orabug: 27403317]

  - x86: Display correct settings for the SPECTRE_V2 bug
    (Kanth Ghatraju) 

  - Set CONFIG_GENERIC_CPU_VULNERABILITIES flag (Kanth
    Ghatraju) [Orabug: 27403317]

  - x86/cpu: Implement CPU vulnerabilites sysfs functions
    (Thomas Gleixner) [Orabug: 27403317]

  - sysfs/cpu: Fix typos in vulnerability documentation
    (David Woodhouse) 

  - sysfs/cpu: Add vulnerability folder (Thomas Gleixner)
    [Orabug: 27403317]

  - x86/cpufeatures: Add X86_BUG_SPECTRE_V[12] (David
    Woodhouse) [Orabug: 27403317]

  - x86/cpufeatures: Add X86_BUG_CPU_MELTDOWN (Kanth
    Ghatraju) [Orabug: 27403317]

  - KVM: x86: Add memory barrier on vmcs field lookup
    (Andrew Honig) (CVE-2017-5753)

  - KVM: VMX: remove I/O port 0x80 bypass on Intel hosts
    (Andrew Honig) [Orabug: 27402301] (CVE-2017-1000407)
    (CVE-2017-1000407)

  - xfs: give all workqueues rescuer threads (Chris Mason)
    [Orabug: 27397568]

  - ixgbevf: handle mbox_api_13 in ixgbevf_change_mtu (Joao
    Martins)"
  );
  # https://oss.oracle.com/pipermail/oraclevm-errata/2018-January/000822.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?026e66b2"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected kernel-uek / kernel-uek-firmware packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:C/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:vm:kernel-uek");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:vm:kernel-uek-firmware");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:vm_server:3.4");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/12/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/01/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/01/22");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
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
if (rpm_check(release:"OVS3.4", reference:"kernel-uek-4.1.12-112.14.13.el6uek")) flag++;
if (rpm_check(release:"OVS3.4", reference:"kernel-uek-firmware-4.1.12-112.14.13.el6uek")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "kernel-uek / kernel-uek-firmware");
}
