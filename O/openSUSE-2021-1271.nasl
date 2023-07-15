#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
#
# The package checks in this plugin were extracted from
# openSUSE Security Update openSUSE-SU-2021:1271-1. The text itself
# is copyright (C) SUSE.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(153414);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/09");

  script_cve_id(
    "CVE-2021-3640",
    "CVE-2021-3653",
    "CVE-2021-3656",
    "CVE-2021-3732",
    "CVE-2021-3739",
    "CVE-2021-3743",
    "CVE-2021-3753",
    "CVE-2021-3759",
    "CVE-2021-34556",
    "CVE-2021-35477",
    "CVE-2021-38160",
    "CVE-2021-38198",
    "CVE-2021-38204",
    "CVE-2021-38205",
    "CVE-2021-38207"
  );

  script_name(english:"openSUSE 15 Security Update : kernel (openSUSE-SU-2021:1271-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote SUSE Linux SUSE15 host has packages installed that are affected by multiple vulnerabilities as referenced in
the openSUSE-SU-2021:1271-1 advisory.

  - In the Linux kernel through 5.13.7, an unprivileged BPF program can obtain sensitive information from
    kernel memory via a Speculative Store Bypass side-channel attack because the protection mechanism neglects
    the possibility of uninitialized memory locations on the BPF stack. (CVE-2021-34556)

  - In the Linux kernel through 5.13.7, an unprivileged BPF program can obtain sensitive information from
    kernel memory via a Speculative Store Bypass side-channel attack because a certain preempting store
    operation does not necessarily occur before a store operation that has an attacker-controlled value.
    (CVE-2021-35477)

  - kernel: SVM nested virtualization issue in KVM (AVIC support) (CVE-2021-3653)

  - ** DISPUTED ** In drivers/char/virtio_console.c in the Linux kernel before 5.13.4, data corruption or loss
    can be triggered by an untrusted device that supplies a buf->len value exceeding the buffer size. NOTE:
    the vendor indicates that the cited data corruption is not a vulnerability in any existing use case; the
    length validation was added solely for robustness in the face of anomalous host OS behavior.
    (CVE-2021-38160)

  - arch/x86/kvm/mmu/paging_tmpl.h in the Linux kernel before 5.12.11 incorrectly computes the access
    permissions of a shadow page, leading to a missing guest protection page fault. (CVE-2021-38198)

  - drivers/usb/host/max3421-hcd.c in the Linux kernel before 5.13.6 allows physically proximate attackers to
    cause a denial of service (use-after-free and panic) by removing a MAX-3421 USB device in certain
    situations. (CVE-2021-38204)

  - drivers/net/ethernet/xilinx/xilinx_emaclite.c in the Linux kernel before 5.13.3 makes it easier for
    attackers to defeat an ASLR protection mechanism because it prints a kernel pointer (i.e., the real IOMEM
    pointer). (CVE-2021-38205)

  - drivers/net/ethernet/xilinx/ll_temac_main.c in the Linux kernel before 5.12.13 allows remote attackers to
    cause a denial of service (buffer overflow and lockup) by sending heavy network traffic for about ten
    minutes. (CVE-2021-38207)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1040364");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1124431");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1127650");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1135481");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1152489");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1160010");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1167032");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1168202");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1171420");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1174969");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1175052");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1175543");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1177399");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1180141");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1180347");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1181006");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1181148");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1181972");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1184114");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1184180");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1185675");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1186731");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1187211");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1187455");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1187468");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1187619");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1188067");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1188172");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1188418");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1188439");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1188616");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1188878");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1188885");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1188924");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1188982");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1188983");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1188985");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1189153");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1189197");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1189209");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1189210");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1189212");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1189213");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1189214");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1189215");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1189216");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1189217");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1189218");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1189219");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1189220");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1189221");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1189222");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1189229");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1189262");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1189291");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1189292");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1189298");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1189301");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1189305");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1189323");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1189384");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1189385");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1189392");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1189399");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1189400");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1189427");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1189449");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1189503");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1189504");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1189505");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1189506");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1189507");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1189562");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1189563");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1189564");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1189565");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1189566");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1189567");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1189568");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1189569");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1189573");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1189574");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1189575");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1189576");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1189577");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1189579");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1189581");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1189582");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1189583");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1189585");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1189586");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1189587");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1189706");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1189760");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1189832");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1189841");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1189870");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1189883");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1190022");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1190025");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1190115");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1190117");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1190131");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1190181");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1190358");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1190412");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1190428");
  # https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/TKO35W4C75JOXT46ZWC6Y4OFM23PXCNX/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?45c08ea3");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-34556");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-35477");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-3640");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-3653");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-3656");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-3732");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-3739");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-3743");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-3753");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-3759");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-38160");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-38198");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-38204");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-38205");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-38207");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-38160");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2021-3656");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/08/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/09/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/09/16");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-debug-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-default-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-default-base-rebuild");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-default-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-kvmsmall");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-kvmsmall-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-macros");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-obs-build");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-obs-qa");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-preempt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-preempt-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-source");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-source-vanilla");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-syms");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.2");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"SuSE Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/SuSE/release", "Host/SuSE/rpm-list");

  exit(0);
}


include('audit.inc');
include('global_settings.inc');
include('misc_func.inc');
include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var release = get_kb_item('Host/SuSE/release');
if (isnull(release) || release =~ "^(SLED|SLES)") audit(AUDIT_OS_NOT, 'openSUSE');
var os_ver = pregmatch(pattern: "^SUSE([\d.]+)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'openSUSE');
os_ver = os_ver[1];
if (release !~ "^(SUSE15\.2)$") audit(AUDIT_OS_RELEASE_NOT, 'openSUSE', '15.2', release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'openSUSE ' + os_ver, cpu);

var pkgs = [
    {'reference':'kernel-debug-5.3.18-lp152.92.2', 'cpu':'x86_64', 'release':'SUSE15.2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-debug-devel-5.3.18-lp152.92.2', 'cpu':'x86_64', 'release':'SUSE15.2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-default-5.3.18-lp152.92.2', 'cpu':'x86_64', 'release':'SUSE15.2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-default-base-5.3.18-lp152.92.2.lp152.8.42.3', 'cpu':'x86_64', 'release':'SUSE15.2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-default-base-rebuild-5.3.18-lp152.92.2.lp152.8.42.3', 'cpu':'x86_64', 'release':'SUSE15.2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-default-devel-5.3.18-lp152.92.2', 'cpu':'x86_64', 'release':'SUSE15.2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-devel-5.3.18-lp152.92.2', 'release':'SUSE15.2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-kvmsmall-5.3.18-lp152.92.2', 'cpu':'x86_64', 'release':'SUSE15.2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-kvmsmall-devel-5.3.18-lp152.92.2', 'cpu':'x86_64', 'release':'SUSE15.2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-macros-5.3.18-lp152.92.2', 'release':'SUSE15.2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-obs-build-5.3.18-lp152.92.2', 'cpu':'x86_64', 'release':'SUSE15.2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-obs-qa-5.3.18-lp152.92.1', 'cpu':'x86_64', 'release':'SUSE15.2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-preempt-5.3.18-lp152.92.2', 'cpu':'x86_64', 'release':'SUSE15.2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-preempt-devel-5.3.18-lp152.92.2', 'cpu':'x86_64', 'release':'SUSE15.2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-source-5.3.18-lp152.92.2', 'release':'SUSE15.2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-source-vanilla-5.3.18-lp152.92.2', 'release':'SUSE15.2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-syms-5.3.18-lp152.92.1', 'cpu':'x86_64', 'release':'SUSE15.2', 'rpm_spec_vers_cmp':TRUE}
];

var flag = 0;
foreach package_array ( pkgs ) {
  var reference = NULL;
  var release = NULL;
  var cpu = NULL;
  var rpm_spec_vers_cmp = NULL;
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (!empty_or_null(package_array['release'])) release = package_array['release'];
  if (!empty_or_null(package_array['cpu'])) cpu = package_array['cpu'];
  if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
  if (reference && release) {
    if (rpm_check(release:release, cpu:cpu, reference:reference, rpm_spec_vers_cmp:rpm_spec_vers_cmp)) flag++;
  }
}

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
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'kernel-debug / kernel-debug-devel / kernel-default / etc');
}
