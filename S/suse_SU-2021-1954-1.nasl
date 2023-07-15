#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
#
# The package checks in this plugin were extracted from
# SUSE update advisory SUSE-SU-2021:1954-1. The text itself
# is copyright (C) SUSE.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(150729);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/08/09");

  script_cve_id(
    "CVE-2021-21284",
    "CVE-2021-21285",
    "CVE-2021-21334",
    "CVE-2021-30465"
  );
  script_xref(name:"SuSE", value:"SUSE-SU-2021:1954-1");

  script_name(english:"SUSE SLES15 Security Update : containerd, docker, runc (SUSE-SU-2021:1954-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote SUSE Linux SLES15 host has packages installed that are affected by multiple vulnerabilities as referenced in
the SUSE-SU-2021:1954-1 advisory.

  - In Docker before versions 9.03.15, 20.10.3 there is a vulnerability involving the --userns-remap option in
    which access to remapped root allows privilege escalation to real root. When using --userns-remap, if
    the root user in the remapped namespace has access to the host filesystem they can modify files under
    /var/lib/docker/ that cause writing files with extended privileges. Versions 20.10.3 and
    19.03.15 contain patches that prevent privilege escalation from remapped user. (CVE-2021-21284)

  - In Docker before versions 9.03.15, 20.10.3 there is a vulnerability in which pulling an intentionally
    malformed Docker image manifest crashes the dockerd daemon. Versions 20.10.3 and 19.03.15 contain patches
    that prevent the daemon from crashing. (CVE-2021-21285)

  - In containerd (an industry-standard container runtime) before versions 1.3.10 and 1.4.4, containers
    launched through containerd's CRI implementation (through Kubernetes, crictl, or any other pod/container
    client that uses the containerd CRI service) that share the same image may receive incorrect environment
    variables, including values that are defined for other containers. If the affected containers have
    different security contexts, this may allow sensitive information to be unintentionally shared. If you are
    not using containerd's CRI implementation (through one of the mechanisms described above), you are not
    vulnerable to this issue. If you are not launching multiple containers or Kubernetes pods from the same
    image which have different environment variables, you are not vulnerable to this issue. If you are not
    launching multiple containers or Kubernetes pods from the same image in rapid succession, you have reduced
    likelihood of being vulnerable to this issue This vulnerability has been fixed in containerd 1.3.10 and
    containerd 1.4.4. Users should update to these versions. (CVE-2021-21334)

  - runc before 1.0.0-rc95 allows a Container Filesystem Breakout via Directory Traversal. To exploit the
    vulnerability, an attacker must be able to create multiple containers with a fairly specific mount
    configuration. The problem occurs via a symlink-exchange attack that relies on a race condition.
    (CVE-2021-30465)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1168481");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1175081");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1175821");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1181594");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1181641");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1181677");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1181730");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1181732");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1181749");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1182451");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1182476");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1182947");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1183024");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1183855");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1184768");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1184962");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1185405");
  # https://lists.suse.com/pipermail/sle-security-updates/2021-June/008994.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?5583c074");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-21284");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-21285");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-21334");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-30465");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:L/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-30465");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/02/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/06/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/06/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:containerd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:docker");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:docker-bash-completion");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:docker-fish-completion");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:runc");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:15");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"SuSE Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/SuSE/release", "Host/SuSE/rpm-list");

  exit(0);
}


include('audit.inc');
include('global_settings.inc');
include('misc_func.inc');
include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var release = get_kb_item("Host/SuSE/release");
if (isnull(release) || release !~ "^(SLED|SLES)") audit(AUDIT_OS_NOT, "SUSE");
var os_ver = pregmatch(pattern: "^(SLE(S|D)\d+)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'SUSE');
os_ver = os_ver[1];
if (! preg(pattern:"^(SLES15)$", string:os_ver)) audit(AUDIT_OS_NOT, 'SUSE SLES15', 'SUSE ' + os_ver);

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'SUSE ' + os_ver, cpu);

var sp = get_kb_item("Host/SuSE/patchlevel");
if (isnull(sp)) sp = "0";
if (os_ver == "SLES15" && (! preg(pattern:"^(0|1|2|3)$", string:sp))) audit(AUDIT_OS_NOT, "SLES15 SP0/1/2/3", os_ver + " SP" + sp);

var pkgs = [
    {'reference':'containerd-1.4.4-5.32', 'sp':'0', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-15'},
    {'reference':'docker-20.10.6_ce-6.49', 'sp':'0', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-15'},
    {'reference':'docker-bash-completion-20.10.6_ce-6.49', 'sp':'0', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-15'},
    {'reference':'runc-1.0.0~rc93-1.14', 'sp':'0', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-15'},
    {'reference':'containerd-1.4.4-5.32', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-15.1'},
    {'reference':'docker-20.10.6_ce-6.49', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-15.1'},
    {'reference':'docker-bash-completion-20.10.6_ce-6.49', 'sp':'1', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-15.1'},
    {'reference':'runc-1.0.0~rc93-1.14', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-15.1'},
    {'reference':'containerd-1.4.4-5.32', 'sp':'1', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLE_HPC-ESPOS-release-1'},
    {'reference':'containerd-1.4.4-5.32', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLE_HPC-ESPOS-release-1'},
    {'reference':'docker-20.10.6_ce-6.49', 'sp':'1', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLE_HPC-ESPOS-release-1'},
    {'reference':'docker-20.10.6_ce-6.49', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLE_HPC-ESPOS-release-1'},
    {'reference':'docker-bash-completion-20.10.6_ce-6.49', 'sp':'1', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLE_HPC-ESPOS-release-1'},
    {'reference':'runc-1.0.0~rc93-1.14', 'sp':'1', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLE_HPC-ESPOS-release-1'},
    {'reference':'runc-1.0.0~rc93-1.14', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLE_HPC-ESPOS-release-1'},
    {'reference':'containerd-1.4.4-5.32', 'sp':'0', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLE_HPC-ESPOS-release-15'},
    {'reference':'containerd-1.4.4-5.32', 'sp':'0', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLE_HPC-ESPOS-release-15'},
    {'reference':'docker-20.10.6_ce-6.49', 'sp':'0', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLE_HPC-ESPOS-release-15'},
    {'reference':'docker-20.10.6_ce-6.49', 'sp':'0', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLE_HPC-ESPOS-release-15'},
    {'reference':'docker-bash-completion-20.10.6_ce-6.49', 'sp':'0', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLE_HPC-ESPOS-release-15'},
    {'reference':'docker-bash-completion-20.10.6_ce-6.49', 'sp':'0', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLE_HPC-ESPOS-release-15'},
    {'reference':'runc-1.0.0~rc93-1.14', 'sp':'0', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLE_HPC-ESPOS-release-15'},
    {'reference':'runc-1.0.0~rc93-1.14', 'sp':'0', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLE_HPC-ESPOS-release-15'},
    {'reference':'containerd-1.4.4-5.32', 'sp':'0', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLE_HPC-LTSS-release-15'},
    {'reference':'containerd-1.4.4-5.32', 'sp':'0', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLE_HPC-LTSS-release-15'},
    {'reference':'docker-20.10.6_ce-6.49', 'sp':'0', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLE_HPC-LTSS-release-15'},
    {'reference':'docker-20.10.6_ce-6.49', 'sp':'0', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLE_HPC-LTSS-release-15'},
    {'reference':'docker-bash-completion-20.10.6_ce-6.49', 'sp':'0', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLE_HPC-LTSS-release-15'},
    {'reference':'docker-bash-completion-20.10.6_ce-6.49', 'sp':'0', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLE_HPC-LTSS-release-15'},
    {'reference':'runc-1.0.0~rc93-1.14', 'sp':'0', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLE_HPC-LTSS-release-15'},
    {'reference':'runc-1.0.0~rc93-1.14', 'sp':'0', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLE_HPC-LTSS-release-15'},
    {'reference':'containerd-1.4.4-5.32', 'sp':'1', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLE_HPC-LTSS-release-15.1'},
    {'reference':'containerd-1.4.4-5.32', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLE_HPC-LTSS-release-15.1'},
    {'reference':'docker-20.10.6_ce-6.49', 'sp':'1', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLE_HPC-LTSS-release-15.1'},
    {'reference':'docker-20.10.6_ce-6.49', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLE_HPC-LTSS-release-15.1'},
    {'reference':'docker-bash-completion-20.10.6_ce-6.49', 'sp':'1', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLE_HPC-LTSS-release-15.1'},
    {'reference':'runc-1.0.0~rc93-1.14', 'sp':'1', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLE_HPC-LTSS-release-15.1'},
    {'reference':'runc-1.0.0~rc93-1.14', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLE_HPC-LTSS-release-15.1'},
    {'reference':'containerd-1.4.4-5.32', 'sp':'2', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-containers-release-15.2'},
    {'reference':'docker-20.10.6_ce-6.49', 'sp':'2', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-containers-release-15.2'},
    {'reference':'docker-bash-completion-20.10.6_ce-6.49', 'sp':'2', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-containers-release-15.2'},
    {'reference':'runc-1.0.0~rc93-1.14', 'sp':'2', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-containers-release-15.2'},
    {'reference':'containerd-1.4.4-5.32', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-containers-release-15.3'},
    {'reference':'docker-20.10.6_ce-6.49', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-containers-release-15.3'},
    {'reference':'docker-bash-completion-20.10.6_ce-6.49', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-containers-release-15.3'},
    {'reference':'docker-fish-completion-20.10.6_ce-6.49', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-containers-release-15.3'},
    {'reference':'runc-1.0.0~rc93-1.14', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-containers-release-15.3'},
    {'reference':'containerd-1.4.4-5.32', 'sp':'0', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-ltss-release-15'},
    {'reference':'docker-20.10.6_ce-6.49', 'sp':'0', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-ltss-release-15'},
    {'reference':'docker-bash-completion-20.10.6_ce-6.49', 'sp':'0', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-ltss-release-15'},
    {'reference':'runc-1.0.0~rc93-1.14', 'sp':'0', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-ltss-release-15'},
    {'reference':'containerd-1.4.4-5.32', 'sp':'1', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-ltss-release-15.1'},
    {'reference':'docker-20.10.6_ce-6.49', 'sp':'1', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-ltss-release-15.1'},
    {'reference':'docker-bash-completion-20.10.6_ce-6.49', 'sp':'1', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-ltss-release-15.1'},
    {'reference':'runc-1.0.0~rc93-1.14', 'sp':'1', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-ltss-release-15.1'},
    {'reference':'containerd-1.4.4-5.32', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-15.1'},
    {'reference':'docker-20.10.6_ce-6.49', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-15.1'},
    {'reference':'docker-bash-completion-20.10.6_ce-6.49', 'sp':'1', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-15.1'},
    {'reference':'runc-1.0.0~rc93-1.14', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-15.1'}
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
  var ltss_plugin_caveat = NULL;
  if(ltss_caveat_required) ltss_plugin_caveat = '\n' +
    'NOTE: This vulnerability check contains fixes that apply to\n' +
    'packages only available in SUSE Enterprise Linux Server LTSS\n' +
    'repositories. Access to these package security updates require\n' +
    'a paid SUSE LTSS subscription.\n';
  security_report_v4(
      port       : 0,
      severity   : SECURITY_WARNING,
      extra      : rpm_report_get() + ltss_plugin_caveat
  );
  exit(0);
}
else
{
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'containerd / docker / docker-bash-completion / docker-fish-completion / etc');
}
