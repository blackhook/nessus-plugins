#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
#
# The package checks in this plugin were extracted from
# SUSE update advisory SUSE-SU-2021:2352-1. The text itself
# is copyright (C) SUSE.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(151760);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/09");

  script_cve_id(
    "CVE-2021-0512",
    "CVE-2021-0605",
    "CVE-2021-3573",
    "CVE-2021-33624",
    "CVE-2021-34693"
  );
  script_xref(name:"SuSE", value:"SUSE-SU-2021:2352-1");

  script_name(english:"SUSE SLED15 / SLES15 Security Update : kernel (SUSE-SU-2021:2352-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote SUSE Linux SLED15 / SLES15 host has packages installed that are affected by multiple vulnerabilities as
referenced in the SUSE-SU-2021:2352-1 advisory.

  - In __hidinput_change_resolution_multipliers of hid-input.c, there is a possible out of bounds write due to
    a heap buffer overflow. This could lead to local escalation of privilege with no additional execution
    privileges needed. User interaction is not needed for exploitation.Product: AndroidVersions: Android
    kernelAndroid ID: A-173843328References: Upstream kernel (CVE-2021-0512)

  - In pfkey_dump of af_key.c, there is a possible out-of-bounds read due to a missing bounds check. This
    could lead to local information disclosure in the kernel with System execution privileges needed. User
    interaction is not needed for exploitation.Product: AndroidVersions: Android kernelAndroid ID: A-110373476
    (CVE-2021-0605)

  - In kernel/bpf/verifier.c in the Linux kernel before 5.12.13, a branch can be mispredicted (e.g., because
    of type confusion) and consequently an unprivileged BPF program can read arbitrary memory locations via a
    side-channel attack, aka CID-9183671af6db. (CVE-2021-33624)

  - net/can/bcm.c in the Linux kernel through 5.12.10 allows local users to obtain sensitive information from
    kernel stack memory because parts of a data structure are uninitialized. (CVE-2021-34693)

  - To fix this vulnerability, update the affected packages: linux linux-rt (CVE-2021-3573)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1152489");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1153274");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1154353");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1155518");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1164648");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1176447");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1176774");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1176919");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1177028");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1178134");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1182470");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1184212");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1184685");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1185486");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1185675");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1185677");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1186206");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1186666");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1186949");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1187171");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1187263");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1187356");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1187402");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1187403");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1187404");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1187407");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1187408");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1187409");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1187410");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1187411");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1187412");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1187413");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1187452");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1187554");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1187595");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1187601");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1187795");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1187867");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1187883");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1187886");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1187927");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1187972");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1187980");
  # https://lists.suse.com/pipermail/sle-security-updates/2021-July/009149.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?66c29436");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-0512");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-0605");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-33624");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-34693");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-3573");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-3573");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2021-0512");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/06/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/07/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/07/16");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:cluster-md-kmp-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:dlm-kmp-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:gfs2-kmp-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-64kb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-64kb-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-default-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-default-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-default-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-default-livepatch");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-default-livepatch-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-livepatch-5_3_18-59_13-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-macros");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-obs-build");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-preempt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-preempt-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-preempt-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-source");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-syms");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-zfcpdump");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:ocfs2-kmp-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:reiserfs-kmp-default");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:15");
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
if (! preg(pattern:"^(SLED15|SLES15)$", string:os_ver)) audit(AUDIT_OS_NOT, 'SUSE SLED15 / SLES15', 'SUSE ' + os_ver);

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'SUSE ' + os_ver, cpu);

var sp = get_kb_item("Host/SuSE/patchlevel");
if (isnull(sp)) sp = "0";
if (os_ver == "SLED15" && (! preg(pattern:"^(3)$", string:sp))) audit(AUDIT_OS_NOT, "SLED15 SP3", os_ver + " SP" + sp);
if (os_ver == "SLES15" && (! preg(pattern:"^(3)$", string:sp))) audit(AUDIT_OS_NOT, "SLES15 SP3", os_ver + " SP" + sp);

var pkgs = [
    {'reference':'cluster-md-kmp-default-5.3.18-59.13.1', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-ha-release-15.3'},
    {'reference':'dlm-kmp-default-5.3.18-59.13.1', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-ha-release-15.3'},
    {'reference':'gfs2-kmp-default-5.3.18-59.13.1', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-ha-release-15.3'},
    {'reference':'ocfs2-kmp-default-5.3.18-59.13.1', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-ha-release-15.3'},
    {'reference':'kernel-64kb-5.3.18-59.13.1', 'sp':'3', 'cpu':'aarch64', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-basesystem-release-15.3'},
    {'reference':'kernel-64kb-5.3.18-59.13.1', 'sp':'3', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-basesystem-release-15.3'},
    {'reference':'kernel-64kb-devel-5.3.18-59.13.1', 'sp':'3', 'cpu':'aarch64', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-basesystem-release-15.3'},
    {'reference':'kernel-64kb-devel-5.3.18-59.13.1', 'sp':'3', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-basesystem-release-15.3'},
    {'reference':'kernel-default-5.3.18-59.13.1', 'sp':'3', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-basesystem-release-15.3'},
    {'reference':'kernel-default-5.3.18-59.13.1', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-basesystem-release-15.3'},
    {'reference':'kernel-default-base-5.3.18-59.13.1.18.6.1', 'sp':'3', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-basesystem-release-15.3'},
    {'reference':'kernel-default-base-5.3.18-59.13.1.18.6.1', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-basesystem-release-15.3'},
    {'reference':'kernel-default-devel-5.3.18-59.13.1', 'sp':'3', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-basesystem-release-15.3'},
    {'reference':'kernel-default-devel-5.3.18-59.13.1', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-basesystem-release-15.3'},
    {'reference':'kernel-devel-5.3.18-59.13.1', 'sp':'3', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-basesystem-release-15.3'},
    {'reference':'kernel-devel-5.3.18-59.13.1', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-basesystem-release-15.3'},
    {'reference':'kernel-macros-5.3.18-59.13.1', 'sp':'3', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-basesystem-release-15.3'},
    {'reference':'kernel-macros-5.3.18-59.13.1', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-basesystem-release-15.3'},
    {'reference':'kernel-preempt-5.3.18-59.13.1', 'sp':'3', 'cpu':'aarch64', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-basesystem-release-15.3'},
    {'reference':'kernel-preempt-5.3.18-59.13.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-basesystem-release-15.3'},
    {'reference':'kernel-preempt-5.3.18-59.13.1', 'sp':'3', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-basesystem-release-15.3'},
    {'reference':'kernel-preempt-5.3.18-59.13.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-basesystem-release-15.3'},
    {'reference':'kernel-zfcpdump-5.3.18-59.13.1', 'sp':'3', 'cpu':'s390x', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-basesystem-release-15.3'},
    {'reference':'kernel-zfcpdump-5.3.18-59.13.1', 'sp':'3', 'cpu':'s390x', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-basesystem-release-15.3'},
    {'reference':'kernel-obs-build-5.3.18-59.13.1', 'sp':'3', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-development-tools-release-15.3'},
    {'reference':'kernel-obs-build-5.3.18-59.13.1', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-development-tools-release-15.3'},
    {'reference':'kernel-preempt-devel-5.3.18-59.13.1', 'sp':'3', 'cpu':'aarch64', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-development-tools-release-15.3'},
    {'reference':'kernel-preempt-devel-5.3.18-59.13.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-development-tools-release-15.3'},
    {'reference':'kernel-preempt-devel-5.3.18-59.13.1', 'sp':'3', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-development-tools-release-15.3'},
    {'reference':'kernel-preempt-devel-5.3.18-59.13.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-development-tools-release-15.3'},
    {'reference':'kernel-source-5.3.18-59.13.1', 'sp':'3', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-development-tools-release-15.3'},
    {'reference':'kernel-source-5.3.18-59.13.1', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-development-tools-release-15.3'},
    {'reference':'kernel-syms-5.3.18-59.13.1', 'sp':'3', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-development-tools-release-15.3'},
    {'reference':'kernel-syms-5.3.18-59.13.1', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-development-tools-release-15.3'},
    {'reference':'reiserfs-kmp-default-5.3.18-59.13.1', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-legacy-release-15.3'},
    {'reference':'kernel-default-livepatch-5.3.18-59.13.1', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-live-patching-release-15.3'},
    {'reference':'kernel-default-livepatch-devel-5.3.18-59.13.1', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-live-patching-release-15.3'},
    {'reference':'kernel-livepatch-5_3_18-59_13-default-1-7.3.1', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-live-patching-release-15.3'},
    {'reference':'kernel-default-extra-5.3.18-59.13.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-we-release-15.3'},
    {'reference':'kernel-default-extra-5.3.18-59.13.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-we-release-15.3'},
    {'reference':'kernel-preempt-extra-5.3.18-59.13.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-we-release-15.3'},
    {'reference':'kernel-preempt-extra-5.3.18-59.13.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-we-release-15.3'}
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
      severity   : SECURITY_WARNING,
      extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'cluster-md-kmp-default / dlm-kmp-default / gfs2-kmp-default / etc');
}
