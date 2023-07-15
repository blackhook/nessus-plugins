#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# openSUSE Security Update openSUSE-SU-2023:0090-1. The text itself
# is copyright (C) SUSE.
##

include('compat.inc');

if (description)
{
  script_id(174256);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/19");

  script_cve_id(
    "CVE-2022-39331",
    "CVE-2022-39332",
    "CVE-2022-39333",
    "CVE-2022-39334",
    "CVE-2023-23942"
  );

  script_name(english:"openSUSE 15 Security Update : nextcloud-desktop (openSUSE-SU-2023:0090-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote openSUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote openSUSE 15 host has packages installed that are affected by multiple vulnerabilities as referenced in the
openSUSE-SU-2023:0090-1 advisory.

  - Nexcloud desktop is the Desktop sync client for Nextcloud. An attacker can inject arbitrary HyperText
    Markup Language into the Desktop Client application in the notifications. It is recommended that the
    Nextcloud Desktop client is upgraded to 3.6.1. There are no known workarounds for this issue.
    (CVE-2022-39331)

  - Nexcloud desktop is the Desktop sync client for Nextcloud. An attacker can inject arbitrary HyperText
    Markup Language into the Desktop Client application via user status and information. It is recommended
    that the Nextcloud Desktop client is upgraded to 3.6.1. There are no known workarounds for this issue.
    (CVE-2022-39332)

  - Nexcloud desktop is the Desktop sync client for Nextcloud. An attacker can inject arbitrary HyperText
    Markup Language into the Desktop Client application. It is recommended that the Nextcloud Desktop client
    is upgraded to 3.6.1. There are no known workarounds for this issue. (CVE-2022-39333)

  - Nextcloud also ships a CLI utility called nextcloudcmd which is sometimes used for automated scripting and
    headless servers. Versions of nextcloudcmd prior to 3.6.1 would incorrectly trust invalid TLS
    certificates, which may enable a Man-in-the-middle attack that exposes sensitive data or credentials to a
    network attacker. This affects the CLI only. It does not affect the standard GUI desktop Nextcloud
    clients, and it does not affect the Nextcloud server. (CVE-2022-39334)

  - The Nextcloud Desktop Client is a tool to synchronize files from a Nextcloud Server with your computer.
    Versions prior to 3.6.3 are missing sanitisation on qml labels which are used for basic HTML elements such
    as `strong`, `em` and `head` lines in the UI of the desktop client. The lack of sanitisation may allow for
    javascript injection. It is recommended that the Nextcloud Desktop Client is upgraded to 3.6.3. There are
    no known workarounds for this issue. (CVE-2023-23942)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1201070");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1205798");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1205799");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1205800");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1205801");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1207976");
  # https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/IHDC7NYZMDNIUM6KMGVNGTIO5AKPD4O7/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?cd2be336");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-39331");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-39332");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-39333");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-39334");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-23942");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-23942");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/11/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/04/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/04/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:caja-extension-nextcloud");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:cloudproviders-extension-nextcloud");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libnextcloudsync-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libnextcloudsync0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:nautilus-extension-nextcloud");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:nemo-extension-nextcloud");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:nextcloud-desktop");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:nextcloud-desktop-dolphin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:nextcloud-desktop-lang");
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
    {'reference':'caja-extension-nextcloud-3.8.0-bp154.2.3.1', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'cloudproviders-extension-nextcloud-3.8.0-bp154.2.3.1', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libnextcloudsync-devel-3.8.0-bp154.2.3.1', 'cpu':'aarch64', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libnextcloudsync-devel-3.8.0-bp154.2.3.1', 'cpu':'x86_64', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libnextcloudsync0-3.8.0-bp154.2.3.1', 'cpu':'aarch64', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libnextcloudsync0-3.8.0-bp154.2.3.1', 'cpu':'x86_64', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'nautilus-extension-nextcloud-3.8.0-bp154.2.3.1', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'nemo-extension-nextcloud-3.8.0-bp154.2.3.1', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'nextcloud-desktop-3.8.0-bp154.2.3.1', 'cpu':'aarch64', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'nextcloud-desktop-3.8.0-bp154.2.3.1', 'cpu':'x86_64', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'nextcloud-desktop-dolphin-3.8.0-bp154.2.3.1', 'cpu':'aarch64', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'nextcloud-desktop-dolphin-3.8.0-bp154.2.3.1', 'cpu':'x86_64', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'nextcloud-desktop-lang-3.8.0-bp154.2.3.1', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'caja-extension-nextcloud / cloudproviders-extension-nextcloud / etc');
}
