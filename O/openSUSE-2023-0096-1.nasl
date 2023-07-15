#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# openSUSE Security Update openSUSE-SU-2023:0096-1. The text itself
# is copyright (C) SUSE.
##

include('compat.inc');

if (description)
{
  script_id(174915);
  script_version("1.0");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/28");

  script_cve_id("CVE-2023-1350");

  script_name(english:"openSUSE 15 Security Update : liferea (openSUSE-SU-2023:0096-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote openSUSE host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The remote openSUSE 15 host has packages installed that are affected by a vulnerability as referenced in the openSUSE-
SU-2023:0096-1 advisory.

  - A vulnerability was found in liferea. It has been rated as critical. Affected by this issue is the
    function update_job_run of the file src/update.c of the component Feed Enrichment. The manipulation of the
    argument source with the input |date >/tmp/bad-item-link.txt leads to os command injection. The attack
    may be launched remotely. The exploit has been disclosed to the public and may be used. The name of the
    patch is 8d8b5b963fa64c7a2122d1bbfbb0bed46e813e59. It is recommended to apply a patch to fix this issue.
    The identifier of this vulnerability is VDB-222848. (CVE-2023-1350)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1193579");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1209190");
  # https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/U2XWO532L7BXCMKLBA5M4DP7HIU4NSO2/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?5d49f6af");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-1350");
  script_set_attribute(attribute:"solution", value:
"Update the affected liferea and / or liferea-lang packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-1350");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/03/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/04/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/04/28");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:liferea");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:liferea-lang");
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
    {'reference':'liferea-1.14.1-bp154.2.3.1', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'liferea-lang-1.14.1-bp154.2.3.1', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'liferea / liferea-lang');
}
