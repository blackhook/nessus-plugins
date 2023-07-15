#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# SUSE update advisory SUSE-SU-2023:0634-1. The text itself
# is copyright (C) SUSE.
##

include('compat.inc');

if (description)
{
  script_id(172256);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/30");

  script_cve_id(
    "CVE-2017-5754",
    "CVE-2021-4203",
    "CVE-2022-2991",
    "CVE-2022-4662",
    "CVE-2022-36280",
    "CVE-2022-47929",
    "CVE-2023-0045",
    "CVE-2023-0266",
    "CVE-2023-0590"
  );
  script_xref(name:"SuSE", value:"SUSE-SU-2023:0634-1");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2023/04/20");

  script_name(english:"SUSE SLED12 / SLES12 Security Update : kernel (SUSE-SU-2023:0634-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote SUSE Linux SLED12 / SLES12 host has packages installed that are affected by multiple vulnerabilities as
referenced in the SUSE-SU-2023:0634-1 advisory.

  - Systems with microprocessors utilizing speculative execution and indirect branch prediction may allow
    unauthorized disclosure of information to an attacker with local user access via a side-channel analysis
    of the data cache. (CVE-2017-5754)

  - A use-after-free read flaw was found in sock_getsockopt() in net/core/sock.c due to SO_PEERCRED and
    SO_PEERGROUPS race with listen() (and connect()) in the Linux kernel. In this flaw, an attacker with a
    user privileges may crash the system or leak internal kernel information. (CVE-2021-4203)

  - A heap-based buffer overflow was found in the Linux kernel's LightNVM subsystem. The issue results from
    the lack of proper validation of the length of user-supplied data prior to copying it to a fixed-length
    heap-based buffer. This vulnerability allows a local attacker to escalate privileges and execute arbitrary
    code in the context of the kernel. The attacker must first obtain the ability to execute high-privileged
    code on the target system to exploit this vulnerability. (CVE-2022-2991)

  - An out-of-bounds(OOB) memory access vulnerability was found in vmwgfx driver in
    drivers/gpu/vmxgfx/vmxgfx_kms.c in GPU component in the Linux kernel with device file '/dev/dri/renderD128
    (or Dxxx)'. This flaw allows a local attacker with a user account on the system to gain privilege, causing
    a denial of service(DoS). (CVE-2022-36280)

  - A flaw incorrect access control in the Linux kernel USB core subsystem was found in the way user attaches
    usb device. A local user could use this flaw to crash the system. (CVE-2022-4662)

  - In the Linux kernel before 6.1.6, a NULL pointer dereference bug in the traffic control subsystem allows
    an unprivileged user to trigger a denial of service (system crash) via a crafted traffic control
    configuration that is set up with tc qdisc and tc class commands. This affects qdisc_graft in
    net/sched/sch_api.c. (CVE-2022-47929)

  - A flaw was found in the Linux kernel's Layer 2 Tunneling Protocol (L2TP). A missing lock when clearing
    sk_user_data can lead to a race condition and NULL pointer dereference. A local user could use this flaw
    to potentially crash the system causing a denial of service. (CVE-2022-4129) (CVE-2023-0045)

  - A use after free vulnerability exists in the ALSA PCM package in the Linux Kernel.
    SNDRV_CTL_IOCTL_ELEM_{READ|WRITE}32 is missing locks that can be used in a use-after-free that can result
    in a priviledge escalation to gain ring0 access from the system user. We recommend upgrading past commit
    56b88b50565cd8b946a2d00b0c83927b7ebb055e (CVE-2023-0266)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1068032");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1175995");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1186449");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1194535");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1198971");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1201420");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1202195");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1202712");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1202713");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1203200");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1203332");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1203693");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1204356");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1204514");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1204662");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1205149");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1205397");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1205495");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1206602");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1206635");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1206640");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1206641");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1206642");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1206643");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1206645");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1206646");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1206648");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1206649");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1206664");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1206677");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1206698");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1206784");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1206855");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1206858");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1206873");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1206876");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1206877");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1206878");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1206880");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1206882");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1206883");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1206884");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1206885");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1206887");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1206888");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1206890");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1207092");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1207093");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1207094");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1207097");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1207102");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1207103");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1207104");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1207107");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1207108");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1207134");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1207186");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1207201");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1207237");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1207773");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1207795");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1207875");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1208108");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1208541");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1208570");
  # https://lists.suse.com/pipermail/sle-security-updates/2023-March/013982.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?dfff965c");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2017-5754");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-4203");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-2991");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-36280");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-4662");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-47929");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-0045");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-0266");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-0590");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:P/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-4203");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2023-0266");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/01/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/03/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/03/08");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:cluster-md-kmp-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:dlm-kmp-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:gfs2-kmp-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-default-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-default-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-default-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-default-kgraft");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-default-kgraft-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-default-man");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-macros");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-obs-build");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-source");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-syms");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kgraft-patch-4_12_14-122_150-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:ocfs2-kmp-default");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:12");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"SuSE Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/SuSE/release", "Host/SuSE/rpm-list");

  exit(0);
}


include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item("Host/SuSE/release");
if (isnull(os_release) || os_release !~ "^(SLED|SLES)") audit(AUDIT_OS_NOT, "SUSE");
var os_ver = pregmatch(pattern: "^(SLE(S|D)\d+)", string:os_release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'SUSE');
os_ver = os_ver[1];
if (! preg(pattern:"^(SLED12|SLES12)$", string:os_ver)) audit(AUDIT_OS_NOT, 'SUSE SLED12 / SLES12', 'SUSE (' + os_ver + ')');

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'SUSE (' + os_ver + ')', cpu);

var service_pack = get_kb_item("Host/SuSE/patchlevel");
if (isnull(service_pack)) service_pack = "0";
if (os_ver == "SLED12" && (! preg(pattern:"^(5)$", string:service_pack))) audit(AUDIT_OS_NOT, "SLED12 SP5", os_ver + " SP" + service_pack);
if (os_ver == "SLES12" && (! preg(pattern:"^(5)$", string:service_pack))) audit(AUDIT_OS_NOT, "SLES12 SP5", os_ver + " SP" + service_pack);

var pkgs = [
    {'reference':'kernel-default-4.12.14-122.150.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5', 'sles-release-12.5']},
    {'reference':'kernel-default-base-4.12.14-122.150.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5', 'sles-release-12.5']},
    {'reference':'kernel-default-devel-4.12.14-122.150.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5', 'sles-release-12.5']},
    {'reference':'kernel-default-extra-4.12.14-122.150.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLED12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5', 'sle-we-release-12.5', 'sles-release-12.5']},
    {'reference':'kernel-default-extra-4.12.14-122.150.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5', 'sle-we-release-12.5', 'sles-release-12.5']},
    {'reference':'kernel-default-man-4.12.14-122.150.1', 'sp':'5', 'cpu':'s390x', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5', 'sles-release-12.5']},
    {'reference':'kernel-devel-4.12.14-122.150.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5', 'sles-release-12.5']},
    {'reference':'kernel-macros-4.12.14-122.150.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5', 'sles-release-12.5']},
    {'reference':'kernel-obs-build-4.12.14-122.150.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5', 'sle-sdk-release-12.5', 'sles-release-12.5']},
    {'reference':'kernel-source-4.12.14-122.150.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5', 'sles-release-12.5']},
    {'reference':'kernel-syms-4.12.14-122.150.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5', 'sles-release-12.5']},
    {'reference':'cluster-md-kmp-default-4.12.14-122.150.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-ha-release-12.5']},
    {'reference':'dlm-kmp-default-4.12.14-122.150.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-ha-release-12.5']},
    {'reference':'gfs2-kmp-default-4.12.14-122.150.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-ha-release-12.5']},
    {'reference':'ocfs2-kmp-default-4.12.14-122.150.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-ha-release-12.5']},
    {'reference':'kernel-default-kgraft-4.12.14-122.150.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-live-patching-release-12.5']},
    {'reference':'kernel-default-kgraft-devel-4.12.14-122.150.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-live-patching-release-12.5']},
    {'reference':'kgraft-patch-4_12_14-122_150-default-1-8.3.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-live-patching-release-12.5']}
];

var ltss_caveat_required = FALSE;
var flag = 0;
foreach var package_array ( pkgs ) {
  var reference = NULL;
  var _release = NULL;
  var sp = NULL;
  var _cpu = NULL;
  var exists_check = NULL;
  var rpm_spec_vers_cmp = NULL;
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (!empty_or_null(package_array['release'])) _release = package_array['release'];
  if (!empty_or_null(package_array['sp'])) sp = package_array['sp'];
  if (!empty_or_null(package_array['cpu'])) _cpu = package_array['cpu'];
  if (!empty_or_null(package_array['exists_check'])) exists_check = package_array['exists_check'];
  if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
  if (reference && _release) {
    if (exists_check) {
      var check_flag = 0;
      foreach var check (exists_check) {
        if (!rpm_exists(release:_release, rpm:check)) continue;
        check_flag++;
      }
      if (!check_flag) continue;
    }
    if (rpm_check(release:_release, sp:sp, cpu:_cpu, reference:reference, rpm_spec_vers_cmp:rpm_spec_vers_cmp)) flag++;
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
