#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# openSUSE Security Update openSUSE-SU-2023:0137-1. The text itself
# is copyright (C) SUSE.
##

include('compat.inc');

if (description)
{
  script_id(177676);
  script_version("1.0");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/06/28");

  script_cve_id("CVE-2016-8605", "CVE-2020-17354");

  script_name(english:"openSUSE 15 Security Update : guile1, lilypond (openSUSE-SU-2023:0137-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote openSUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote openSUSE 15 host has packages installed that are affected by multiple vulnerabilities as referenced in the
openSUSE-SU-2023:0137-1 advisory.

  - The mkdir procedure of GNU Guile temporarily changed the process' umask to zero. During that time window,
    in a multithreaded application, other threads could end up creating files with insecure permissions. For
    example, mkdir without the optional mode argument would create directories as 0777. This is fixed in Guile
    2.0.13. Prior versions are affected. (CVE-2016-8605)

  - LilyPond before 2.24 allows attackers to bypass the -dsafe protection mechanism via output-def-lookup or
    output-def-scope, as demonstrated by dangerous Scheme code in a .ly file that causes arbitrary code
    execution during conversion to a different file format. NOTE: in 2.24 and later versions, safe mode is
    removed, and the product no longer tries to block code execution when external files are used.
    (CVE-2020-17354)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1210502");
  # https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/ROLJCNPWZ2G4IQWP7NQKXNBT2QR32K2A/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d7dd891a");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2016-8605");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-17354");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2016-8605");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2020-17354");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/10/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/06/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/06/28");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:guile1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:guile1-modules-2_2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libguile-2_2-1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libguile1-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:lilypond");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:lilypond-emmentaler-fonts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:lilypond-fonts-common");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.4");
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
var os_release = get_kb_item('Host/SuSE/release');
if (isnull(os_release) || os_release =~ "^(SLED|SLES)") audit(AUDIT_OS_NOT, 'openSUSE');
var _os_ver = pregmatch(pattern: "^SUSE([\d.]+)", string:os_release);
if (isnull(_os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'openSUSE');
_os_ver = _os_ver[1];
if (os_release !~ "^(SUSE15\.4)$") audit(AUDIT_OS_RELEASE_NOT, 'openSUSE', '15.4', os_release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'openSUSE ' + _os_ver, cpu);

var pkgs = [
    {'reference':'guile1-2.2.6-bp154.3.3.1', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'guile1-modules-2_2-2.2.6-bp154.3.3.1', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libguile-2_2-1-2.2.6-bp154.3.3.1', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libguile1-devel-2.2.6-bp154.3.3.1', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'lilypond-2.24.1-bp154.2.3.2', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'lilypond-emmentaler-fonts-2.24.1-bp154.2.3.2', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'lilypond-fonts-common-2.24.1-bp154.2.3.2', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE}
];

var flag = 0;
foreach package_array ( pkgs ) {
  var reference = NULL;
  var _release = NULL;
  var _cpu = NULL;
  var rpm_spec_vers_cmp = NULL;
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (!empty_or_null(package_array['release'])) _release = package_array['release'];
  if (!empty_or_null(package_array['cpu'])) cpu = package_array['cpu'];
  if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
  if (reference && _release) {
    if (rpm_check(release:_release, cpu:_cpu, reference:reference, rpm_spec_vers_cmp:rpm_spec_vers_cmp)) flag++;
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'guile1 / guile1-modules-2_2 / libguile-2_2-1 / libguile1-devel / etc');
}
