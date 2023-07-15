#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# SUSE update advisory SUSE-SU-2022:3333-1. The text itself
# is copyright (C) SUSE.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(165333);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/02/08");

  script_cve_id("CVE-2022-1798", "CVE-2022-1996", "CVE-2022-29162");
  script_xref(name:"SuSE", value:"SUSE-SU-2022:3333-1");

  script_name(english:"SUSE SLES15 / openSUSE 15 Security Update : kubevirt, virt-api-container, virt-controller-container, virt-handler-container, virt-launcher-container, virt-libguestfs-tools-container, virt-operator-container (SUSE-SU-2022:3333-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote SUSE Linux SLES15 / openSUSE 15 host has packages installed that are affected by multiple vulnerabilities as
referenced in the SUSE-SU-2022:3333-1 advisory.

  - A path traversal vulnerability in KubeVirt versions up to 0.56 (and 0.55.1) on all platforms allows a user
    able to configure the kubevirt to read arbitrary files on the host filesystem which are publicly readable
    or which are readable for UID 107 or GID 107. /proc/self/<> is not accessible. (CVE-2022-1798)

  - Authorization Bypass Through User-Controlled Key in GitHub repository emicklei/go-restful prior to v3.8.0.
    (CVE-2022-1996)

  - runc is a CLI tool for spawning and running containers on Linux according to the OCI specification. A bug
    was found in runc prior to version 1.1.2 where `runc exec --cap` created processes with non-empty
    inheritable Linux process capabilities, creating an atypical Linux environment and enabling programs with
    inheritable file capabilities to elevate those capabilities to the permitted set during execve(2). This
    bug did not affect the container security sandbox as the inheritable set never contained more capabilities
    than were included in the container's bounding set. This bug has been fixed in runc 1.1.2. This fix
    changes `runc exec --cap` behavior such that the additional capabilities granted to the process being
    executed (as specified via `--cap` arguments) do not include inheritable capabilities. In addition, `runc
    spec` is changed to not set any inheritable capabilities in the created example OCI spec (`config.json`)
    file. (CVE-2022-29162)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1199392");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1199460");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1199603");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1200528");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1202516");
  # https://lists.suse.com/pipermail/sle-security-updates/2022-September/012328.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ee45e1c2");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-1798");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-1996");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-29162");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-1996");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/05/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/09/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/09/23");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kubevirt-manifests");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kubevirt-virtctl");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:15");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"SuSE Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/SuSE/release", "Host/SuSE/rpm-list");

  exit(0);
}


include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item("Host/SuSE/release");
if (isnull(os_release) || os_release !~ "^(SLED|SLES|SUSE)") audit(AUDIT_OS_NOT, "SUSE / openSUSE");
var os_ver = pregmatch(pattern: "^(SLE(S|D)\d+|SUSE([\d.]+))", string:os_release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'SUSE / openSUSE');
os_ver = os_ver[1];
if (! preg(pattern:"^(SLES15|SUSE15\.4)$", string:os_ver)) audit(AUDIT_OS_NOT, 'SUSE SLES15 / openSUSE 15', 'SUSE / openSUSE (' + os_ver + ')');

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'SUSE / openSUSE (' + os_ver + ')', cpu);

var service_pack = get_kb_item("Host/SuSE/patchlevel");
if (isnull(service_pack)) service_pack = "0";
if (os_ver == "SLES15" && (! preg(pattern:"^(4)$", string:service_pack))) audit(AUDIT_OS_NOT, "SLES15 SP4", os_ver + " SP" + service_pack);

var pkgs = [
    {'reference':'kubevirt-manifests-0.54.0-150400.3.3.2', 'sp':'4', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4', 'SLE_HPC-release-15.4', 'sle-module-containers-release-15.4', 'sles-release-15.4']},
    {'reference':'kubevirt-virtctl-0.54.0-150400.3.3.2', 'sp':'4', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4', 'SLE_HPC-release-15.4', 'sle-module-containers-release-15.4', 'sles-release-15.4']},
    {'reference':'kubevirt-container-disk-0.54.0-150400.3.3.2', 'cpu':'x86_64', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'kubevirt-manifests-0.54.0-150400.3.3.2', 'cpu':'x86_64', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'kubevirt-tests-0.54.0-150400.3.3.2', 'cpu':'x86_64', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'kubevirt-virt-api-0.54.0-150400.3.3.2', 'cpu':'x86_64', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'kubevirt-virt-controller-0.54.0-150400.3.3.2', 'cpu':'x86_64', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'kubevirt-virt-handler-0.54.0-150400.3.3.2', 'cpu':'x86_64', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'kubevirt-virt-launcher-0.54.0-150400.3.3.2', 'cpu':'x86_64', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'kubevirt-virt-operator-0.54.0-150400.3.3.2', 'cpu':'x86_64', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'kubevirt-virtctl-0.54.0-150400.3.3.2', 'cpu':'x86_64', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'obs-service-kubevirt_containers_meta-0.54.0-150400.3.3.2', 'cpu':'x86_64', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'kubevirt-container-disk / kubevirt-manifests / kubevirt-tests / etc');
}
