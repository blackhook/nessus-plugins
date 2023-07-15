#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
#
# The package checks in this plugin were extracted from
# openSUSE Security Update openSUSE-SU-2022:0845-1. The text itself
# is copyright (C) SUSE.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(159043);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/03/17");

  script_cve_id("CVE-2020-14367");

  script_name(english:"openSUSE 15 Security Update : chrony (openSUSE-SU-2022:0845-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The remote SUSE Linux SUSE15 host has packages installed that are affected by a vulnerability as referenced in the
openSUSE-SU-2022:0845-1 advisory.

  - A flaw was found in chrony versions before 3.5.1 when creating the PID file under the /var/run/chrony
    folder. The file is created during chronyd startup while still running as the root user, and when it's
    opened for writing, chronyd does not check for an existing symbolic link with the same file name. This
    flaw allows an attacker with privileged access to create a symlink with the default PID file name pointing
    to any destination file in the system, resulting in data loss and a denial of service due to the path
    traversal. (CVE-2020-14367)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1099272");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1115529");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1128846");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1162964");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1172113");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1173277");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1174075");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1174911");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1180689");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1181826");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1187906");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1190926");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1194229");
  # https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/GIUHNUKYNY5JRZHWXP7NXCJOMX4HEQMQ/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?67ec2b5b");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-14367");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:N/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:H/UI:N/S:U/C:N/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-14367");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/08/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/03/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/03/17");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:augeas");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:augeas-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:augeas-devel-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:augeas-lense-tests");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:augeas-lenses");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:chrony");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:chrony-pool-empty");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:chrony-pool-openSUSE");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:chrony-pool-suse");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libaugeas0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libaugeas0-32bit");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.3");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"SuSE Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (release !~ "^(SUSE15\.3)$") audit(AUDIT_OS_RELEASE_NOT, 'openSUSE', '15.3', release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'openSUSE ' + os_ver, cpu);

var pkgs = [
    {'reference':'augeas-1.10.1-3.9.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'augeas-devel-1.10.1-3.9.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'augeas-devel-32bit-1.10.1-3.9.1', 'cpu':'x86_64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'augeas-lense-tests-1.10.1-3.9.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'augeas-lenses-1.10.1-3.9.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'chrony-4.1-150300.16.3.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'chrony-pool-empty-4.1-150300.16.3.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'chrony-pool-openSUSE-4.1-150300.16.3.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'chrony-pool-suse-4.1-150300.16.3.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libaugeas0-1.10.1-3.9.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libaugeas0-32bit-1.10.1-3.9.1', 'cpu':'x86_64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE}
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
      severity   : SECURITY_NOTE,
      extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'augeas / augeas-devel / augeas-devel-32bit / augeas-lense-tests / etc');
}
