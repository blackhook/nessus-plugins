#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
#
# The package checks in this plugin were extracted from
# openSUSE Security Update openSUSE-SU-2022:0727-1. The text itself
# is copyright (C) SUSE.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(158640);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/21");

  script_cve_id("CVE-2021-3995", "CVE-2021-3996");

  script_name(english:"openSUSE 15 Security Update : libeconf, shadow and util-linux (openSUSE-SU-2022:0727-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote SUSE Linux SUSE15 host has packages installed that are affected by multiple vulnerabilities as referenced in
the openSUSE-SU-2022:0727-1 advisory.

  - A logic error was found in the libmount library of util-linux in the function that allows an unprivileged
    user to unmount a FUSE filesystem. This flaw allows a local user on a vulnerable system to unmount other
    users' filesystems that are either world-writable themselves (like /tmp) or mounted in a world-writable
    directory. An attacker may use this flaw to cause a denial of service to applications that use the
    affected filesystems. (CVE-2021-3996)

  - A logic error was found in the libmount library of util-linux in the function that allows an unprivileged
    user to unmount a FUSE filesystem. This flaw allows an unprivileged local attacker to unmount FUSE
    filesystems that belong to certain other users who have a UID that is a prefix of the UID of the attacker
    in its string form. An attacker may use this flaw to cause a denial of service to applications that use
    the affected filesystems. (CVE-2021-3995)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1188507");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1192954");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1193632");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1194976");
  # https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/GUBUSLRBG42MLRL65HHMLIWQIKS3SKKP/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?630d9106");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-3995");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-3996");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-3996");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/03/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/03/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/03/05");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libblkid-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libblkid-devel-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libblkid-devel-static");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libblkid1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libblkid1-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libeconf-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libeconf0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libeconf0-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libfdisk-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libfdisk-devel-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libfdisk-devel-static");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libfdisk1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libfdisk1-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libmount-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libmount-devel-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libmount-devel-static");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libmount1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libmount1-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsmartcols-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsmartcols-devel-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsmartcols-devel-static");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsmartcols1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsmartcols1-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libuuid-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libuuid-devel-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libuuid-devel-static");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libuuid1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libuuid1-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:login_defs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python3-libmount");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:shadow");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:util-linux");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:util-linux-lang");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:util-linux-systemd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:uuidd");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.3");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"SuSE Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
    {'reference':'libblkid-devel-2.36.2-150300.4.14.3', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libblkid-devel-32bit-2.36.2-150300.4.14.3', 'cpu':'x86_64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libblkid-devel-static-2.36.2-150300.4.14.3', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libblkid1-2.36.2-150300.4.14.3', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libblkid1-32bit-2.36.2-150300.4.14.3', 'cpu':'x86_64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libeconf-devel-0.4.4+git20220104.962774f-150300.3.6.2', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libeconf0-0.4.4+git20220104.962774f-150300.3.6.2', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libeconf0-32bit-0.4.4+git20220104.962774f-150300.3.6.2', 'cpu':'x86_64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libfdisk-devel-2.36.2-150300.4.14.3', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libfdisk-devel-32bit-2.36.2-150300.4.14.3', 'cpu':'x86_64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libfdisk-devel-static-2.36.2-150300.4.14.3', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libfdisk1-2.36.2-150300.4.14.3', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libfdisk1-32bit-2.36.2-150300.4.14.3', 'cpu':'x86_64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libmount-devel-2.36.2-150300.4.14.3', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libmount-devel-32bit-2.36.2-150300.4.14.3', 'cpu':'x86_64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libmount-devel-static-2.36.2-150300.4.14.3', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libmount1-2.36.2-150300.4.14.3', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libmount1-32bit-2.36.2-150300.4.14.3', 'cpu':'x86_64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libsmartcols-devel-2.36.2-150300.4.14.3', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libsmartcols-devel-32bit-2.36.2-150300.4.14.3', 'cpu':'x86_64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libsmartcols-devel-static-2.36.2-150300.4.14.3', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libsmartcols1-2.36.2-150300.4.14.3', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libsmartcols1-32bit-2.36.2-150300.4.14.3', 'cpu':'x86_64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libuuid-devel-2.36.2-150300.4.14.3', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libuuid-devel-32bit-2.36.2-150300.4.14.3', 'cpu':'x86_64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libuuid-devel-static-2.36.2-150300.4.14.3', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libuuid1-2.36.2-150300.4.14.3', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libuuid1-32bit-2.36.2-150300.4.14.3', 'cpu':'x86_64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'login_defs-4.8.1-150300.4.3.8', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3-libmount-2.36.2-150300.4.14.2', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'shadow-4.8.1-150300.4.3.8', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'util-linux-2.36.2-150300.4.14.3', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'util-linux-lang-2.36.2-150300.4.14.3', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'util-linux-systemd-2.36.2-150300.4.14.2', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'uuidd-2.36.2-150300.4.14.2', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE}
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
      severity   : SECURITY_WARNING,
      extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'libblkid-devel / libblkid-devel-32bit / libblkid-devel-static / etc');
}
