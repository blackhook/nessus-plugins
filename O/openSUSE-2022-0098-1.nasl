#%NASL_MIN_LEVEL 70300
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# openSUSE Security Update openSUSE-SU-2022:0098-1. The text itself
# is copyright (C) SUSE.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(159458);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/01");

  script_cve_id("CVE-2021-41239", "CVE-2021-41241", "CVE-2021-41741");

  script_name(english:"openSUSE 15 Security Update : nextcloud (openSUSE-SU-2022:0098-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote SUSE Linux SUSE15 host has packages installed that are affected by multiple vulnerabilities as referenced in
the openSUSE-SU-2022:0098-1 advisory.

  - Nextcloud server is a self hosted system designed to provide cloud style services. In affected versions
    the User Status API did not consider the user enumeration settings by the administrator. This allowed a
    user to enumerate other users on the instance, even when user listings where disabled. It is recommended
    that the Nextcloud Server is upgraded to 20.0.14, 21.0.6 or 22.2.1. There are no known workarounds.
    (CVE-2021-41239)

  - Nextcloud server is a self hosted system designed to provide cloud style services. The groupfolders
    application for Nextcloud allows sharing a folder with a group of people. In addition, it allows setting
    advanced permissions on subfolders, for example, a user could be granted access to the groupfolder but
    not specific subfolders. Due to a lacking permission check in affected versions, a user could still access
    these subfolders by copying the groupfolder to another location. It is recommended that the Nextcloud
    Server is upgraded to 20.0.14, 21.0.6 or 22.2.1. Users unable to upgrade should disable the groupfolders
    application in the admin settings. (CVE-2021-41241)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1196905");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1196908");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1196952");
  # https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/EZTHEQMMIKP2RX3EBMXDQAOIVUPMCDFB/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ab8d4f48");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-41239");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-41241");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-41741");
  script_set_attribute(attribute:"solution", value:
"Update the affected nextcloud and / or nextcloud-apache packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-41239");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/03/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/03/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/04/01");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:nextcloud");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:nextcloud-apache");
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
    {'reference':'nextcloud-21.0.9-bp153.2.12.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'nextcloud-apache-21.0.9-bp153.2.12.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'nextcloud / nextcloud-apache');
}
