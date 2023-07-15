#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
#
# The package checks in this plugin were extracted from
# openSUSE Security Update openSUSE-SU-2021:1082-1. The text itself
# is copyright (C) SUSE.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(152057);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/01/20");

  script_cve_id("CVE-2021-33910");
  script_xref(name:"IAVA", value:"2021-A-0350");

  script_name(english:"openSUSE 15 Security Update : systemd (openSUSE-SU-2021:1082-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The remote SUSE Linux SUSE15 host has packages installed that are affected by a vulnerability as referenced in the
openSUSE-SU-2021:1082-1 advisory.

  - basic/unit-name.c in systemd prior to 246.15, 247.8, 248.5, and 249.1 has a Memory Allocation with an
    Excessive Size Value (involving strdupa and alloca for a pathname controlled by a local attacker) that
    results in an operating system crash. (CVE-2021-33910)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1184994");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1188063");
  # https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/AAGPKC3S3ZQN25VD5T76IP4JJFCIWE4R/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?2b213ecc");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-33910");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-33910");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/07/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/07/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/07/24");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsystemd0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsystemd0-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsystemd0-mini");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libudev-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libudev-devel-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libudev-mini-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libudev-mini1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libudev1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libudev1-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:nss-myhostname");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:nss-myhostname-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:nss-mymachines");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:nss-mymachines-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:nss-systemd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:systemd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:systemd-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:systemd-bash-completion");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:systemd-container");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:systemd-coredump");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:systemd-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:systemd-journal-remote");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:systemd-logger");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:systemd-mini");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:systemd-mini-bash-completion");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:systemd-mini-container-mini");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:systemd-mini-coredump-mini");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:systemd-mini-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:systemd-mini-sysvinit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:systemd-network");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:systemd-sysvinit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:udev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:udev-mini");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.2");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"SuSE Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/SuSE/release", "Host/SuSE/rpm-list");

  exit(0);
}


include('audit.inc');
include('global_settings.inc');
include('misc_func.inc');
include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item('Host/SuSE/release');
if (isnull(release) || release =~ "^(SLED|SLES)") audit(AUDIT_OS_NOT, 'openSUSE');
os_ver = pregmatch(pattern: "^SUSE([\d.]+)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'openSUSE');
os_ver = os_ver[1];
if (release !~ "^(SUSE15\.2)$") audit(AUDIT_OS_RELEASE_NOT, 'openSUSE', '15.2', release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'openSUSE ' + os_ver, cpu);

pkgs = [
    {'reference':'libsystemd0-234-lp152.31.31.1', 'release':'SUSE15.2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libsystemd0-32bit-234-lp152.31.31.1', 'cpu':'x86_64', 'release':'SUSE15.2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libsystemd0-mini-234-lp152.31.31.1', 'release':'SUSE15.2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libudev-devel-234-lp152.31.31.1', 'release':'SUSE15.2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libudev-devel-32bit-234-lp152.31.31.1', 'cpu':'x86_64', 'release':'SUSE15.2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libudev-mini-devel-234-lp152.31.31.1', 'release':'SUSE15.2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libudev-mini1-234-lp152.31.31.1', 'release':'SUSE15.2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libudev1-234-lp152.31.31.1', 'release':'SUSE15.2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libudev1-32bit-234-lp152.31.31.1', 'cpu':'x86_64', 'release':'SUSE15.2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'nss-myhostname-234-lp152.31.31.1', 'release':'SUSE15.2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'nss-myhostname-32bit-234-lp152.31.31.1', 'cpu':'x86_64', 'release':'SUSE15.2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'nss-mymachines-234-lp152.31.31.1', 'release':'SUSE15.2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'nss-mymachines-32bit-234-lp152.31.31.1', 'cpu':'x86_64', 'release':'SUSE15.2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'nss-systemd-234-lp152.31.31.1', 'release':'SUSE15.2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'systemd-234-lp152.31.31.1', 'release':'SUSE15.2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'systemd-32bit-234-lp152.31.31.1', 'cpu':'x86_64', 'release':'SUSE15.2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'systemd-bash-completion-234-lp152.31.31.1', 'release':'SUSE15.2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'systemd-container-234-lp152.31.31.1', 'release':'SUSE15.2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'systemd-coredump-234-lp152.31.31.1', 'release':'SUSE15.2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'systemd-devel-234-lp152.31.31.1', 'release':'SUSE15.2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'systemd-journal-remote-234-lp152.31.31.1', 'release':'SUSE15.2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'systemd-logger-234-lp152.31.31.1', 'release':'SUSE15.2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'systemd-mini-234-lp152.31.31.1', 'release':'SUSE15.2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'systemd-mini-bash-completion-234-lp152.31.31.1', 'release':'SUSE15.2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'systemd-mini-container-mini-234-lp152.31.31.1', 'release':'SUSE15.2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'systemd-mini-coredump-mini-234-lp152.31.31.1', 'release':'SUSE15.2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'systemd-mini-devel-234-lp152.31.31.1', 'release':'SUSE15.2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'systemd-mini-sysvinit-234-lp152.31.31.1', 'release':'SUSE15.2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'systemd-network-234-lp152.31.31.1', 'release':'SUSE15.2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'systemd-sysvinit-234-lp152.31.31.1', 'release':'SUSE15.2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'udev-234-lp152.31.31.1', 'release':'SUSE15.2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'udev-mini-234-lp152.31.31.1', 'release':'SUSE15.2', 'rpm_spec_vers_cmp':TRUE}
];

flag = 0;
foreach package_array ( pkgs ) {
  reference = NULL;
  release = NULL;
  cpu = NULL;
  rpm_spec_vers_cmp = NULL;
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
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'libsystemd0 / libsystemd0-32bit / libsystemd0-mini / libudev-devel / etc');
}
