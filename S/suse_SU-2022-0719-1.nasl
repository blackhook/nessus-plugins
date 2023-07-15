#%NASL_MIN_LEVEL 70300
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# SUSE update advisory SUSE-SU-2022:0719-1. The text itself
# is copyright (C) SUSE.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(159155);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/10");

  script_cve_id("CVE-2022-23648");
  script_xref(name:"SuSE", value:"SUSE-SU-2022:0719-1");

  script_name(english:"SUSE SLES12 Security Update : containerd (SUSE-SU-2022:0719-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The remote SUSE Linux SLES12 host has a package installed that is affected by a vulnerability as referenced in the SUSE-
SU-2022:0719-1 advisory.

  - containerd is a container runtime available as a daemon for Linux and Windows. A bug was found in
    containerd prior to versions 1.6.1, 1.5.10, and 1.14.12 where containers launched through containerd's CRI
    implementation on Linux with a specially-crafted image configuration could gain access to read-only copies
    of arbitrary files and directories on the host. This may bypass any policy-based enforcement on container
    setup (including a Kubernetes Pod Security Policy) and expose potentially sensitive information.
    Kubernetes and crictl can both be configured to use containerd's CRI implementation. This bug has been
    fixed in containerd 1.6.1, 1.5.10, and 1.4.12. Users should update to these versions to resolve the issue.
    (CVE-2022-23648)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1196441");
  # https://lists.suse.com/pipermail/sle-security-updates/2022-March/010359.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a1793e52");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-23648");
  script_set_attribute(attribute:"solution", value:
"Update the affected containerd package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-23648");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/03/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/03/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/03/22");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:containerd");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:12");
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
if (isnull(os_release) || os_release !~ "^(SLED|SLES)") audit(AUDIT_OS_NOT, "SUSE");
var os_ver = pregmatch(pattern: "^(SLE(S|D)\d+)", string:os_release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'SUSE');
os_ver = os_ver[1];
if (! preg(pattern:"^(SLES12)$", string:os_ver)) audit(AUDIT_OS_NOT, 'SUSE SLES12', 'SUSE (' + os_ver + ')');

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'SUSE (' + os_ver + ')', cpu);

var service_pack = get_kb_item("Host/SuSE/patchlevel");
if (isnull(service_pack)) service_pack = "0";
if (os_ver == "SLES12" && (! preg(pattern:"^(0|3|4|5)$", string:service_pack))) audit(AUDIT_OS_NOT, "SLES12 SP0/3/4/5", os_ver + " SP" + service_pack);

var pkgs = [
    {'reference':'containerd-1.4.13-16.54.1', 'sp':'0', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12', 'SLES_SAP-release-12.3', 'SLES_SAP-release-12.4', 'SLES_SAP-release-12.5', 'SLE_HPC-release-12', 'sle-module-containers-release-12-0', 'sles-release-12', 'sles-release-12.3', 'sles-release-12.4', 'sles-release-12.5']},
    {'reference':'containerd-1.4.13-16.54.1', 'sp':'3', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12', 'SLES_SAP-release-12.3', 'SLES_SAP-release-12.4', 'SLES_SAP-release-12.5', 'SLE_HPC-release-12', 'sle-module-containers-release-12-0', 'sles-release-12', 'sles-release-12.3', 'sles-release-12.4', 'sles-release-12.5']},
    {'reference':'containerd-1.4.13-16.54.1', 'sp':'4', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12', 'SLES_SAP-release-12.3', 'SLES_SAP-release-12.4', 'SLES_SAP-release-12.5', 'SLE_HPC-release-12', 'sle-module-containers-release-12-0', 'sles-release-12', 'sles-release-12.3', 'sles-release-12.4', 'sles-release-12.5']},
    {'reference':'containerd-1.4.13-16.54.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12', 'SLES_SAP-release-12.3', 'SLES_SAP-release-12.4', 'SLES_SAP-release-12.5', 'SLE_HPC-release-12', 'sle-module-containers-release-12-0', 'sles-release-12', 'sles-release-12.3', 'sles-release-12.4', 'sles-release-12.5']}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'containerd');
}
