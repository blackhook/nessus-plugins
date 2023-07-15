#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# openSUSE Security Update openSUSE-SU-2022:10187-1. The text itself
# is copyright (C) SUSE.
##

include('compat.inc');

if (description)
{
  script_id(166899);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/11/28");

  script_cve_id(
    "CVE-2022-24949",
    "CVE-2022-24950",
    "CVE-2022-24951",
    "CVE-2022-24952"
  );

  script_name(english:"openSUSE 15 Security Update : EternalTerminal (openSUSE-SU-2022:10187-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote SUSE Linux SUSE15 host has a package installed that is affected by multiple vulnerabilities as referenced in
the openSUSE-SU-2022:10187-1 advisory.

  - A privilege escalation to root exists in Eternal Terminal prior to version 6.2.0. This is due to the
    combination of a race condition, buffer overflow, and logic bug all in PipeSocketHandler::listen().
    (CVE-2022-24949)

  - A race condition exists in Eternal Terminal prior to version 6.2.0 that allows an authenticated attacker
    to hijack other users' SSH authorization socket, enabling the attacker to login to other systems as the
    targeted users. The bug is in UserTerminalRouter::getInfoForId(). (CVE-2022-24950)

  - A race condition exists in Eternal Terminal prior to version 6.2.0 which allows a local attacker to hijack
    Eternal Terminal's IPC socket, enabling access to Eternal Terminal clients which attempt to connect in the
    future. (CVE-2022-24951)

  - Several denial of service vulnerabilities exist in Eternal Terminal prior to version 6.2.0, including a
    DoS triggered remotely by an invalid sequence number and a local bug triggered by invalid input sent
    directly to the IPC socket. (CVE-2022-24952)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1202432");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1202433");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1202434");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1202435");
  # https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/JH3ZAC25EJQ7SSVMLKBZFLS6IEAXTLZ2/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?3cecc26f");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-24949");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-24950");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-24951");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-24952");
  script_set_attribute(attribute:"solution", value:
"Update the affected EternalTerminal package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-24950");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/08/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/11/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/11/03");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:EternalTerminal");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.3");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"SuSE Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (os_release !~ "^(SUSE15\.3)$") audit(AUDIT_OS_RELEASE_NOT, 'openSUSE', '15.3', os_release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'openSUSE ' + _os_ver, cpu);

var pkgs = [
    {'reference':'EternalTerminal-6.2.1-bp153.2.3.1', 'cpu':'aarch64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'EternalTerminal-6.2.1-bp153.2.3.1', 'cpu':'x86_64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE}
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
      severity   : SECURITY_HOLE,
      extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'EternalTerminal');
}
