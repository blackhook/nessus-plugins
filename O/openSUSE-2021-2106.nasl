#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
#
# The package checks in this plugin were extracted from
# openSUSE Security Update openSUSE-SU-2021:2106-1. The text itself
# is copyright (C) SUSE.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(151732);
  script_version("1.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/25");

  script_cve_id(
    "CVE-2018-15750",
    "CVE-2018-15751",
    "CVE-2020-11651",
    "CVE-2020-11652",
    "CVE-2020-25592",
    "CVE-2021-25315",
    "CVE-2021-31607"
  );
  script_xref(name:"IAVA", value:"2020-A-0195-S");
  script_xref(name:"IAVA", value:"2021-A-0524-S");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/05/03");
  script_xref(name:"CEA-ID", value:"CEA-2020-0134");
  script_xref(name:"CEA-ID", value:"CEA-2020-0041");

  script_name(english:"openSUSE 15 Security Update : salt (openSUSE-SU-2021:2106-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote SUSE Linux SUSE15 host has packages installed that are affected by multiple vulnerabilities as referenced in
the openSUSE-SU-2021:2106-1 advisory.

  - Directory Traversal vulnerability in salt-api in SaltStack Salt before 2017.7.8 and 2018.3.x before
    2018.3.3 allows remote attackers to determine which files exist on the server. (CVE-2018-15750)

  - SaltStack Salt before 2017.7.8 and 2018.3.x before 2018.3.3 allow remote attackers to bypass
    authentication and execute arbitrary commands via salt-api(netapi). (CVE-2018-15751)

  - An issue was discovered in SaltStack Salt before 2019.2.4 and 3000 before 3000.2. The salt-master process
    ClearFuncs class does not properly validate method calls. This allows a remote user to access some methods
    without authentication. These methods can be used to retrieve user tokens from the salt master and/or run
    arbitrary commands on salt minions. (CVE-2020-11651)

  - An issue was discovered in SaltStack Salt before 2019.2.4 and 3000 before 3000.2. The salt-master process
    ClearFuncs class allows access to some methods that improperly sanitize paths. These methods allow
    arbitrary directory access to authenticated users. (CVE-2020-11652)

  - In SaltStack Salt through 3002, salt-netapi improperly validates eauth credentials and tokens. A user can
    bypass authentication and invoke Salt SSH. (CVE-2020-25592)

  - A Incorrect Implementation of Authentication Algorithm vulnerability in of SUSE SUSE Linux Enterprise
    Server 15 SP 3; openSUSE Tumbleweed allows local attackers to execute arbitrary code via salt without the
    need to specify valid credentials. This issue affects: SUSE SUSE Linux Enterprise Server 15 SP 3 salt
    versions prior to 3002.2-3. openSUSE Tumbleweed salt version 3002.2-2.1 and prior versions.
    (CVE-2021-25315)

  - In SaltStack Salt 2016.9 through 3002.6, a command injection vulnerability exists in the snapper module
    that allows for local privilege escalation on a minion. The attack requires that a file is created with a
    pathname that is backed up by snapper, and that the master calls the snapper.diff function (which executes
    popen unsafely). (CVE-2021-31607)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1171257");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1176293");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1179831");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1181368");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1182281");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1182293");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1182382");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1185092");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1185281");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1186674");
  # https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/MU6P3NIODW6ZMC4HZLBROO6ZEOD5KAUX/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?410d07bc");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2018-15750");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2018-15751");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-11651");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-11652");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-25592");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-25315");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-31607");
  script_set_attribute(attribute:"solution", value:
"Update the affected python2-distro and / or python3-distro packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-25592");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'SaltStack Salt REST API Arbitrary Command Execution');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:"CANVAS");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/10/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/07/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/07/16");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python2-distro");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python3-distro");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.3");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"SuSE Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (release !~ "^(SUSE15\.3)$") audit(AUDIT_OS_RELEASE_NOT, 'openSUSE', '15.3', release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'openSUSE ' + os_ver, cpu);

pkgs = [
    {'reference':'python2-distro-1.5.0-3.5.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3-distro-1.5.0-3.5.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE}
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
      severity   : SECURITY_HOLE,
      extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'python2-distro / python3-distro');
}
