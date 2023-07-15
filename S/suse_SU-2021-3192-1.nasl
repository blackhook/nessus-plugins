#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
#
# The package checks in this plugin were extracted from
# SUSE update advisory SUSE-SU-2021:3192-1. The text itself
# is copyright (C) SUSE.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(153581);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/05");

  script_cve_id(
    "CVE-2018-9517",
    "CVE-2019-3874",
    "CVE-2019-3900",
    "CVE-2021-3640",
    "CVE-2021-3653",
    "CVE-2021-3656",
    "CVE-2021-3679",
    "CVE-2021-3732",
    "CVE-2021-3753",
    "CVE-2021-3759",
    "CVE-2021-38160",
    "CVE-2021-38198",
    "CVE-2021-38204"
  );
  script_xref(name:"SuSE", value:"SUSE-SU-2021:3192-1");
  script_xref(name:"CEA-ID", value:"CEA-2021-0025");

  script_name(english:"SUSE SLES12 Security Update : kernel (SUSE-SU-2021:3192-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote SUSE Linux SLES12 host has packages installed that are affected by multiple vulnerabilities as referenced in
the SUSE-SU-2021:3192-1 advisory.

  - In pppol2tp_connect, there is possible memory corruption due to a use after free. This could lead to local
    escalation of privilege with System execution privileges needed. User interaction is not needed for
    exploitation. Product: Android. Versions: Android kernel. Android ID: A-38159931. (CVE-2018-9517)

  - The SCTP socket buffer used by a userspace application is not accounted by the cgroups subsystem. An
    attacker can use this flaw to cause a denial of service attack. Kernel 3.10.x and 4.18.x branches are
    believed to be vulnerable. (CVE-2019-3874)

  - An infinite loop issue was found in the vhost_net kernel module in Linux Kernel up to and including
    v5.1-rc6, while handling incoming packets in handle_rx(). It could occur if one end sends packets faster
    than the other end can process them. A guest user, maybe remote one, could use this flaw to stall the
    vhost_net kernel thread, resulting in a DoS scenario. (CVE-2019-3900)

  - kernel: SVM nested virtualization issue in KVM (AVIC support) (CVE-2021-3653)

  - A flaw was found in the KVM's AMD code for supporting SVM nested virtualization. The flaw occurs when
    processing the VMCB (virtual machine control block) provided by the L1 guest to spawn/handle a nested
    guest (L2). Due to improper validation of the int_ctl field, this issue could allow a malicious L1 to
    enable AVIC support (Advanced Virtual Interrupt Controller) for the L2 guest. As a result, the L2 guest
    would be allowed to read/write physical pages of the host, resulting in a crash of the entire system, leak
    of sensitive data or potential guest-to-host escape. (CVE-2021-3653) (CVE-2021-3656, CVE-2021-3732,
    CVE-2021-3753)

  - A lack of CPU resource in the Linux kernel tracing module functionality in versions prior to 5.14-rc3 was
    found in the way user uses trace ring buffer in a specific way. Only privileged local users (with
    CAP_SYS_ADMIN capability) could use this flaw to starve the resources causing denial of service.
    (CVE-2021-3679)

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

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1040364");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1108488");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1114648");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1127650");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1129898");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1133374");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1183050");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1183983");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1185902");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1185973");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1187076");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1188000");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1188172");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1188439");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1188616");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1188885");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1188982");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1189057");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1189262");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1189268");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1189269");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1189270");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1189271");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1189272");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1189291");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1189301");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1189384");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1189385");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1189392");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1189399");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1189400");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1189505");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1189506");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1189562");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1189564");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1189565");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1189566");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1189567");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1189568");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1189569");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1189573");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1189577");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1189579");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1189581");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1189582");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1189639");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1189640");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1189706");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1189846");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1190025");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1190115");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1190117");
  # https://lists.suse.com/pipermail/sle-security-updates/2021-September/009486.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?5c03580a");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2018-9517");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-3874");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-3900");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-3640");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-3653");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-3656");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-3679");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-3732");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-3753");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-3759");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-38160");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-38198");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-38204");
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

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/12/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/09/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/09/23");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-azure");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-azure-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-azure-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-devel-azure");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-source-azure");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-syms-azure");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:12");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"SuSE Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl", "linux_alt_patch_detect.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/SuSE/release", "Host/SuSE/rpm-list");

  exit(0);
}


include('audit.inc');
include('global_settings.inc');
include('misc_func.inc');
include('rpm.inc');
include('ksplice.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var release = get_kb_item("Host/SuSE/release");
if (isnull(release) || release !~ "^(SLED|SLES)") audit(AUDIT_OS_NOT, "SUSE");
var os_ver = pregmatch(pattern: "^(SLE(S|D)\d+)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'SUSE');
os_ver = os_ver[1];
if (! preg(pattern:"^(SLES12)$", string:os_ver)) audit(AUDIT_OS_NOT, 'SUSE SLES12', 'SUSE ' + os_ver);

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'SUSE ' + os_ver, cpu);

var sp = get_kb_item("Host/SuSE/patchlevel");
if (isnull(sp)) sp = "0";
if (os_ver == "SLES12" && (! preg(pattern:"^(5)$", string:sp))) audit(AUDIT_OS_NOT, "SLES12 SP5", os_ver + " SP" + sp);

var pkgs = [
    {'reference':'kernel-azure-4.12.14-16.73.2', 'sp':'5', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-12.5'},
    {'reference':'kernel-azure-base-4.12.14-16.73.2', 'sp':'5', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-12.5'},
    {'reference':'kernel-azure-devel-4.12.14-16.73.2', 'sp':'5', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-12.5'},
    {'reference':'kernel-devel-azure-4.12.14-16.73.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-12.5'},
    {'reference':'kernel-source-azure-4.12.14-16.73.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-12.5'},
    {'reference':'kernel-syms-azure-4.12.14-16.73.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-12.5'},
    {'reference':'kernel-azure-4.12.14-16.73.2', 'sp':'5', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-12.5'},
    {'reference':'kernel-azure-base-4.12.14-16.73.2', 'sp':'5', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-12.5'},
    {'reference':'kernel-azure-devel-4.12.14-16.73.2', 'sp':'5', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-12.5'},
    {'reference':'kernel-devel-azure-4.12.14-16.73.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-12.5'},
    {'reference':'kernel-source-azure-4.12.14-16.73.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-12.5'},
    {'reference':'kernel-syms-azure-4.12.14-16.73.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-12.5'}
];

var ltss_caveat_required = FALSE;
var flag = 0;
foreach package_array ( pkgs ) {
  var reference = NULL;
  var release = NULL;
  var sp = NULL;
  var cpu = NULL;
  var exists_check = NULL;
  var rpm_spec_vers_cmp = NULL;
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (!empty_or_null(package_array['release'])) release = package_array['release'];
  if (!empty_or_null(package_array['sp'])) sp = package_array['sp'];
  if (!empty_or_null(package_array['cpu'])) cpu = package_array['cpu'];
  if (!empty_or_null(package_array['exists_check'])) exists_check = package_array['exists_check'];
  if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
  if (reference && release) {
    if (exists_check) {
      if (!rpm_exists(release:release, rpm:exists_check)) continue;
      if ('ltss' >< tolower(exists_check)) ltss_caveat_required = TRUE;
    }
    if (rpm_check(release:release, sp:sp, cpu:cpu, reference:reference, rpm_spec_vers_cmp:rpm_spec_vers_cmp)) flag++;
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'kernel-azure / kernel-azure-base / kernel-azure-devel / etc');
}
