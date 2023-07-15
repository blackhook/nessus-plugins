#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# SUSE update advisory SUSE-SU-2022:4606-1. The text itself
# is copyright (C) SUSE.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(169282);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/02/08");

  script_cve_id(
    "CVE-2021-21272",
    "CVE-2022-1996",
    "CVE-2022-23524",
    "CVE-2022-23525",
    "CVE-2022-23526"
  );
  script_xref(name:"SuSE", value:"SUSE-SU-2022:4606-1");

  script_name(english:"SUSE SLED15 / SLES15 / openSUSE 15 Security Update : helm (SUSE-SU-2022:4606-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote SUSE Linux SLED15 / SLES15 / openSUSE 15 host has packages installed that are affected by multiple
vulnerabilities as referenced in the SUSE-SU-2022:4606-1 advisory.

  - ORAS is open source software which enables a way to push OCI Artifacts to OCI Conformant registries. ORAS
    is both a CLI for initial testing and a Go Module. In ORAS from version 0.4.0 and before version 0.9.0,
    there is a zip-slip vulnerability. The directory support feature allows the downloaded gzipped tarballs
    to be automatically extracted to the user-specified directory where the tarball can have symbolic links
    and hard links. A well-crafted tarball or tarballs allow malicious artifact providers linking, writing, or
    overwriting specific files on the host filesystem outside of the user-specified directory unexpectedly
    with the same permissions as the user who runs `oras pull`. Users of the affected versions are impacted if
    they are `oras` CLI users who runs `oras pull`, or if they are Go programs, which invoke
    `github.com/deislabs/oras/pkg/content.FileStore`. The problem has been fixed in version 0.9.0. For `oras`
    CLI users, there is no workarounds other than pulling from a trusted artifact provider. For `oras` package
    users, the workaround is to not use `github.com/deislabs/oras/pkg/content.FileStore`, and use other
    content stores instead, or pull from a trusted artifact provider. (CVE-2021-21272)

  - Authorization Bypass Through User-Controlled Key in GitHub repository emicklei/go-restful prior to v3.8.0.
    (CVE-2022-1996)

  - Helm is a tool for managing Charts, pre-configured Kubernetes resources. Versions prior to 3.10.3 are
    subject to Uncontrolled Resource Consumption, resulting in Denial of Service. Input to functions in the
    _strvals_ package can cause a stack overflow. In Go, a stack overflow cannot be recovered from.
    Applications that use functions from the _strvals_ package in the Helm SDK can have a Denial of Service
    attack when they use this package and it panics. This issue has been patched in 3.10.3. SDK users can
    validate strings supplied by users won't create large arrays causing significant memory usage before
    passing them to the _strvals_ functions. (CVE-2022-23524)

  - Helm is a tool for managing Charts, pre-configured Kubernetes resources. Versions prior to 3.10.3 are
    subject to NULL Pointer Dereference in the _repo_package. The _repo_ package contains a handler that
    processes the index file of a repository. For example, the Helm client adds references to chart
    repositories where charts are managed. The _repo_ package parses the index file of the repository and
    loads it into structures Go can work with. Some index files can cause array data structures to be created
    causing a memory violation. Applications that use the _repo_ package in the Helm SDK to parse an index
    file can suffer a Denial of Service when that input causes a panic that cannot be recovered from. The Helm
    Client will panic with an index file that causes a memory violation panic. Helm is not a long running
    service so the panic will not affect future uses of the Helm client. This issue has been patched in
    3.10.3. SDK users can validate index files that are correctly formatted before passing them to the _repo_
    functions. (CVE-2022-23525)

  - Helm is a tool for managing Charts, pre-configured Kubernetes resources. Versions prior to 3.10.3 are
    subject to NULL Pointer Dereference in the_chartutil_ package that can cause a segmentation violation. The
    _chartutil_ package contains a parser that loads a JSON Schema validation file. For example, the Helm
    client when rendering a chart will validate its values with the schema file. The _chartutil_ package
    parses the schema file and loads it into structures Go can work with. Some schema files can cause array
    data structures to be created causing a memory violation. Applications that use the _chartutil_ package in
    the Helm SDK to parse a schema file can suffer a Denial of Service when that input causes a panic that
    cannot be recovered from. Helm is not a long running service so the panic will not affect future uses of
    the Helm client. This issue has been patched in 3.10.3. SDK users can validate schema files that are
    correctly formatted before passing them to the _chartutil_ functions. (CVE-2022-23526)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1181419");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1206467");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1206469");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1206471");
  # https://lists.suse.com/pipermail/sle-security-updates/2022-December/013326.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?29b487a9");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-21272");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-1996");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-23524");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-23525");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-23526");
  script_set_attribute(attribute:"solution", value:
"Update the affected helm, helm-bash-completion, helm-fish-completion and / or helm-zsh-completion packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-1996");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/01/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/12/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/12/23");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:helm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:helm-bash-completion");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:helm-fish-completion");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:helm-zsh-completion");
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
if (! preg(pattern:"^(SLED15|SLES15|SUSE15\.3|SUSE15\.4)$", string:os_ver)) audit(AUDIT_OS_NOT, 'SUSE SLED15 / SLES15 / openSUSE 15', 'SUSE / openSUSE (' + os_ver + ')');

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'SUSE / openSUSE (' + os_ver + ')', cpu);

var service_pack = get_kb_item("Host/SuSE/patchlevel");
if (isnull(service_pack)) service_pack = "0";
if (os_ver == "SLED15" && (! preg(pattern:"^(4)$", string:service_pack))) audit(AUDIT_OS_NOT, "SLED15 SP4", os_ver + " SP" + service_pack);
if (os_ver == "SLES15" && (! preg(pattern:"^(4)$", string:service_pack))) audit(AUDIT_OS_NOT, "SLES15 SP4", os_ver + " SP" + service_pack);

var pkgs = [
    {'reference':'helm-3.10.3-150000.1.13.1', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4', 'SLE_HPC-release-15.4', 'sle-module-containers-release-15.4', 'sles-release-15.4']},
    {'reference':'helm-bash-completion-3.10.3-150000.1.13.1', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4', 'SLE_HPC-release-15.4', 'sle-module-containers-release-15.4', 'sles-release-15.4']},
    {'reference':'helm-fish-completion-3.10.3-150000.1.13.1', 'sp':'4', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4', 'SLE_HPC-release-15.4', 'sle-module-packagehub-subpackages-release-15.4', 'sled-release-15.4', 'sles-release-15.4']},
    {'reference':'helm-fish-completion-3.10.3-150000.1.13.1', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4', 'SLE_HPC-release-15.4', 'sle-module-packagehub-subpackages-release-15.4', 'sled-release-15.4', 'sles-release-15.4']},
    {'reference':'helm-zsh-completion-3.10.3-150000.1.13.1', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4', 'SLE_HPC-release-15.4', 'sle-module-containers-release-15.4', 'sles-release-15.4']},
    {'reference':'helm-3.10.3-150000.1.13.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.3']},
    {'reference':'helm-bash-completion-3.10.3-150000.1.13.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.3']},
    {'reference':'helm-fish-completion-3.10.3-150000.1.13.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.3']},
    {'reference':'helm-zsh-completion-3.10.3-150000.1.13.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.3']},
    {'reference':'helm-3.10.3-150000.1.13.1', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'helm-bash-completion-3.10.3-150000.1.13.1', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'helm-fish-completion-3.10.3-150000.1.13.1', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'helm-zsh-completion-3.10.3-150000.1.13.1', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'helm / helm-bash-completion / helm-fish-completion / etc');
}
