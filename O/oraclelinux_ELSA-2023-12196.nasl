#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Oracle Linux Security Advisory ELSA-2023-12196.
##

include('compat.inc');

if (description)
{
  script_id(172633);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/30");

  script_cve_id(
    "CVE-2022-4129",
    "CVE-2022-41218",
    "CVE-2022-47929",
    "CVE-2023-0266",
    "CVE-2023-0394",
    "CVE-2023-23454",
    "CVE-2023-23455",
    "CVE-2023-23559"
  );
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2023/04/20");

  script_name(english:"Oracle Linux 8 / 9 : Unbreakable Enterprise kernel (ELSA-2023-12196)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Oracle Linux host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Oracle Linux 8 / 9 host has packages installed that are affected by multiple vulnerabilities as referenced in
the ELSA-2023-12196 advisory.

  - atm_tc_enqueue in net/sched/sch_atm.c in the Linux kernel through 6.1.4 allows attackers to cause a denial
    of service because of type confusion (non-negative numbers can sometimes indicate a TC_ACT_SHOT condition
    rather than valid classification results). (CVE-2023-23455)

  - A flaw was found in the Linux kernel's Layer 2 Tunneling Protocol (L2TP). A missing lock when clearing
    sk_user_data can lead to a race condition and NULL pointer dereference. A local user could use this flaw
    to potentially crash the system causing a denial of service. (CVE-2022-4129)

  - cbq_classify in net/sched/sch_cbq.c in the Linux kernel through 6.1.4 allows attackers to cause a denial
    of service (slab-out-of-bounds read) because of type confusion (non-negative numbers can sometimes
    indicate a TC_ACT_SHOT condition rather than valid classification results). (CVE-2023-23454)

  - A use after free vulnerability exists in the ALSA PCM package in the Linux Kernel.
    SNDRV_CTL_IOCTL_ELEM_{READ|WRITE}32 is missing locks that can be used in a use-after-free that can result
    in a priviledge escalation to gain ring0 access from the system user. We recommend upgrading past commit
    56b88b50565cd8b946a2d00b0c83927b7ebb055e (CVE-2023-0266)

  - In rndis_query_oid in drivers/net/wireless/rndis_wlan.c in the Linux kernel through 6.1.5, there is an
    integer overflow in an addition. (CVE-2023-23559)

  - A NULL pointer dereference flaw was found in rawv6_push_pending_frames in net/ipv6/raw.c in the network
    subcomponent in the Linux kernel. This flaw causes the system to crash. (CVE-2023-0394)

  - In drivers/media/dvb-core/dmxdev.c in the Linux kernel through 5.19.10, there is a use-after-free caused
    by refcount races, affecting dvb_demux_open and dvb_dmxdev_release. (CVE-2022-41218)

  - In the Linux kernel before 6.1.6, a NULL pointer dereference bug in the traffic control subsystem allows
    an unprivileged user to trigger a denial of service (system crash) via a crafted traffic control
    configuration that is set up with tc qdisc and tc class commands. This affects qdisc_graft in
    net/sched/sch_api.c. (CVE-2022-47929)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://linux.oracle.com/errata/ELSA-2023-12196.html");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-23559");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/09/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/03/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/03/17");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:8");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:9");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:bpftool");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-uek");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-uek-container");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-uek-container-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-uek-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-uek-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-uek-debug-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-uek-debug-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-uek-debug-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-uek-debug-modules-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-uek-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-uek-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-uek-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-uek-modules-extra");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Oracle Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("linux_alt_patch_detect.nasl", "ssh_get_info.nasl");
  script_require_keys("Host/OracleLinux", "Host/RedHat/release", "Host/RedHat/rpm-list", "Host/local_checks_enabled");

  exit(0);
}


include('ksplice.inc');
include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item('Host/OracleLinux')) audit(AUDIT_OS_NOT, 'Oracle Linux');
var os_release = get_kb_item("Host/RedHat/release");
if (isnull(os_release) || !pregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux)", string:os_release)) audit(AUDIT_OS_NOT, 'Oracle Linux');
var os_ver = pregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux) .*release ([0-9]+(\.[0-9]+)?)", string:os_release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'Oracle Linux');
os_ver = os_ver[1];
if (! preg(pattern:"^(8|9)([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, 'Oracle Linux 8 / 9', 'Oracle Linux ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Oracle Linux', cpu);

var machine_uptrack_level = get_one_kb_item('Host/uptrack-uname-r');
if (machine_uptrack_level)
{
  var trimmed_uptrack_level = ereg_replace(string:machine_uptrack_level, pattern:"\.(x86_64|i[3-6]86|aarch64)$", replace:'');
  var fixed_uptrack_levels = ['5.15.0-8.91.4.1.el8uek', '5.15.0-8.91.4.1.el9uek'];
  foreach var fixed_uptrack_level ( fixed_uptrack_levels ) {
    if (rpm_spec_vers_cmp(a:trimmed_uptrack_level, b:fixed_uptrack_level) >= 0)
    {
      audit(AUDIT_PATCH_INSTALLED, 'KSplice hotfix for ELSA-2023-12196');
    }
  }
  __rpm_report = 'Running KSplice level of ' + trimmed_uptrack_level + ' does not meet the minimum fixed level of ' + join(fixed_uptrack_levels, sep:' / ') + ' for this advisory.\n\n';
}

var kernel_major_minor = get_kb_item('Host/uname/major_minor');
if (empty_or_null(kernel_major_minor)) exit(1, 'Unable to determine kernel major-minor level.');
var expected_kernel_major_minor = '5.15';
if (kernel_major_minor != expected_kernel_major_minor)
  audit(AUDIT_OS_NOT, 'running kernel level ' + expected_kernel_major_minor + ', it is running kernel level ' + kernel_major_minor);

var pkgs = [
    {'reference':'bpftool-5.15.0-8.91.4.1.el8uek', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'bpftool-5.15.0'},
    {'reference':'bpftool-5.15.0-8.91.4.1.el8uek', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'bpftool-5.15.0'},
    {'reference':'kernel-uek-5.15.0-8.91.4.1.el8uek', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-5.15.0'},
    {'reference':'kernel-uek-5.15.0-8.91.4.1.el8uek', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-5.15.0'},
    {'reference':'kernel-uek-container-5.15.0-8.91.4.1.el8uek', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-container-5.15.0'},
    {'reference':'kernel-uek-container-debug-5.15.0-8.91.4.1.el8uek', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-container-debug-5.15.0'},
    {'reference':'kernel-uek-core-5.15.0-8.91.4.1.el8uek', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-core-5.15.0'},
    {'reference':'kernel-uek-core-5.15.0-8.91.4.1.el8uek', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-core-5.15.0'},
    {'reference':'kernel-uek-debug-5.15.0-8.91.4.1.el8uek', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-debug-5.15.0'},
    {'reference':'kernel-uek-debug-5.15.0-8.91.4.1.el8uek', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-debug-5.15.0'},
    {'reference':'kernel-uek-debug-core-5.15.0-8.91.4.1.el8uek', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-debug-core-5.15.0'},
    {'reference':'kernel-uek-debug-core-5.15.0-8.91.4.1.el8uek', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-debug-core-5.15.0'},
    {'reference':'kernel-uek-debug-devel-5.15.0-8.91.4.1.el8uek', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-debug-devel-5.15.0'},
    {'reference':'kernel-uek-debug-devel-5.15.0-8.91.4.1.el8uek', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-debug-devel-5.15.0'},
    {'reference':'kernel-uek-debug-modules-5.15.0-8.91.4.1.el8uek', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-debug-modules-5.15.0'},
    {'reference':'kernel-uek-debug-modules-5.15.0-8.91.4.1.el8uek', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-debug-modules-5.15.0'},
    {'reference':'kernel-uek-debug-modules-extra-5.15.0-8.91.4.1.el8uek', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-debug-modules-extra-5.15.0'},
    {'reference':'kernel-uek-debug-modules-extra-5.15.0-8.91.4.1.el8uek', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-debug-modules-extra-5.15.0'},
    {'reference':'kernel-uek-devel-5.15.0-8.91.4.1.el8uek', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-devel-5.15.0'},
    {'reference':'kernel-uek-devel-5.15.0-8.91.4.1.el8uek', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-devel-5.15.0'},
    {'reference':'kernel-uek-doc-5.15.0-8.91.4.1.el8uek', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-doc-5.15.0'},
    {'reference':'kernel-uek-modules-5.15.0-8.91.4.1.el8uek', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-modules-5.15.0'},
    {'reference':'kernel-uek-modules-5.15.0-8.91.4.1.el8uek', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-modules-5.15.0'},
    {'reference':'kernel-uek-modules-extra-5.15.0-8.91.4.1.el8uek', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-modules-extra-5.15.0'},
    {'reference':'kernel-uek-modules-extra-5.15.0-8.91.4.1.el8uek', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-modules-extra-5.15.0'},
    {'reference':'bpftool-5.15.0-8.91.4.1.el9uek', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'bpftool-5.15.0'},
    {'reference':'bpftool-5.15.0-8.91.4.1.el9uek', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'bpftool-5.15.0'},
    {'reference':'kernel-uek-5.15.0-8.91.4.1.el9uek', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-5.15.0'},
    {'reference':'kernel-uek-5.15.0-8.91.4.1.el9uek', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-5.15.0'},
    {'reference':'kernel-uek-core-5.15.0-8.91.4.1.el9uek', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-core-5.15.0'},
    {'reference':'kernel-uek-core-5.15.0-8.91.4.1.el9uek', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-core-5.15.0'},
    {'reference':'kernel-uek-debug-5.15.0-8.91.4.1.el9uek', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-debug-5.15.0'},
    {'reference':'kernel-uek-debug-5.15.0-8.91.4.1.el9uek', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-debug-5.15.0'},
    {'reference':'kernel-uek-debug-core-5.15.0-8.91.4.1.el9uek', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-debug-core-5.15.0'},
    {'reference':'kernel-uek-debug-core-5.15.0-8.91.4.1.el9uek', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-debug-core-5.15.0'},
    {'reference':'kernel-uek-debug-devel-5.15.0-8.91.4.1.el9uek', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-debug-devel-5.15.0'},
    {'reference':'kernel-uek-debug-devel-5.15.0-8.91.4.1.el9uek', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-debug-devel-5.15.0'},
    {'reference':'kernel-uek-debug-modules-5.15.0-8.91.4.1.el9uek', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-debug-modules-5.15.0'},
    {'reference':'kernel-uek-debug-modules-5.15.0-8.91.4.1.el9uek', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-debug-modules-5.15.0'},
    {'reference':'kernel-uek-debug-modules-extra-5.15.0-8.91.4.1.el9uek', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-debug-modules-extra-5.15.0'},
    {'reference':'kernel-uek-debug-modules-extra-5.15.0-8.91.4.1.el9uek', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-debug-modules-extra-5.15.0'},
    {'reference':'kernel-uek-devel-5.15.0-8.91.4.1.el9uek', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-devel-5.15.0'},
    {'reference':'kernel-uek-devel-5.15.0-8.91.4.1.el9uek', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-devel-5.15.0'},
    {'reference':'kernel-uek-doc-5.15.0-8.91.4.1.el9uek', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-doc-5.15.0'},
    {'reference':'kernel-uek-modules-5.15.0-8.91.4.1.el9uek', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-modules-5.15.0'},
    {'reference':'kernel-uek-modules-5.15.0-8.91.4.1.el9uek', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-modules-5.15.0'},
    {'reference':'kernel-uek-modules-extra-5.15.0-8.91.4.1.el9uek', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-modules-extra-5.15.0'},
    {'reference':'kernel-uek-modules-extra-5.15.0-8.91.4.1.el9uek', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-modules-extra-5.15.0'}
];

var flag = 0;
foreach var package_array ( pkgs ) {
  var reference = NULL;
  var _release = NULL;
  var sp = NULL;
  var _cpu = NULL;
  var el_string = NULL;
  var rpm_spec_vers_cmp = NULL;
  var epoch = NULL;
  var allowmaj = NULL;
  var exists_check = NULL;
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (!empty_or_null(package_array['release'])) _release = 'EL' + package_array['release'];
  if (!empty_or_null(package_array['sp'])) sp = package_array['sp'];
  if (!empty_or_null(package_array['cpu'])) _cpu = package_array['cpu'];
  if (!empty_or_null(package_array['el_string'])) el_string = package_array['el_string'];
  if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
  if (!empty_or_null(package_array['epoch'])) epoch = package_array['epoch'];
  if (!empty_or_null(package_array['allowmaj'])) allowmaj = package_array['allowmaj'];
  if (!empty_or_null(package_array['exists_check'])) exists_check = package_array['exists_check'];
  if (reference && _release) {
    if (exists_check) {
        if (rpm_exists(release:_release, rpm:exists_check) && rpm_check(release:_release, sp:sp, cpu:cpu, reference:reference, epoch:epoch, el_string:el_string, rpm_spec_vers_cmp:rpm_spec_vers_cmp, allowmaj:allowmaj)) flag++;
    } else {
        if (rpm_check(release:_release, sp:sp, cpu:_cpu, reference:reference, epoch:epoch, el_string:el_string, rpm_spec_vers_cmp:rpm_spec_vers_cmp, allowmaj:allowmaj)) flag++;
    }
  }
}

if (flag)
{
  security_report_v4(
      port       : 0,
      severity   : SECURITY_WARNING,
      extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'bpftool / kernel-uek / kernel-uek-container / etc');
}
