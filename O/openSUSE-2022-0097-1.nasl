#%NASL_MIN_LEVEL 70300
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# openSUSE Security Update openSUSE-SU-2022:0097-1. The text itself
# is copyright (C) SUSE.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(159456);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/01");

  script_cve_id("CVE-2022-24714", "CVE-2022-24715");

  script_name(english:"openSUSE 15 Security Update : icingaweb2 (openSUSE-SU-2022:0097-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote SUSE Linux SUSE15 host has packages installed that are affected by multiple vulnerabilities as referenced in
the openSUSE-SU-2022:0097-1 advisory.

  - Icinga Web 2 is an open source monitoring web interface, framework and command-line interface.
    Installations of Icinga 2 with the IDO writer enabled are affected. If you use service custom variables in
    role restrictions, and you regularly decommission service objects, users with said roles may still have
    access to a collection of content. Note that this only applies if a role has implicitly permitted access
    to hosts, due to permitted access to at least one of their services. If access to a host is permitted by
    other means, no sensible information has been disclosed to unauthorized users. This issue has been
    resolved in versions 2.8.6, 2.9.6 and 2.10 of Icinga Web 2. (CVE-2022-24714)

  - Icinga Web 2 is an open source monitoring web interface, framework and command-line interface.
    Authenticated users, with access to the configuration, can create SSH resource files in unintended
    directories, leading to the execution of arbitrary code. This issue has been resolved in versions 2.8.6,
    2.9.6 and 2.10 of Icinga Web 2. Users unable to upgrade should limit access to the Icinga Web 2
    configuration. (CVE-2022-24715)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1196911");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1196913");
  # https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/IZ3SOPUOKOBQCVEVEU6YPIZRX5AB77WX/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?bb93e4b9");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-24714");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-24715");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-24715");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/03/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/03/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/04/01");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:icingacli");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:icingaweb2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:icingaweb2-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:icingaweb2-vendor-HTMLPurifier");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:icingaweb2-vendor-JShrink");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:icingaweb2-vendor-Parsedown");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:icingaweb2-vendor-dompdf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:icingaweb2-vendor-lessphp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:icingaweb2-vendor-zf1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php-Icinga");
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
    {'reference':'icingacli-2.8.6-bp153.2.3.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'icingaweb2-2.8.6-bp153.2.3.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'icingaweb2-common-2.8.6-bp153.2.3.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'icingaweb2-vendor-HTMLPurifier-2.8.6-bp153.2.3.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'icingaweb2-vendor-JShrink-2.8.6-bp153.2.3.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'icingaweb2-vendor-Parsedown-2.8.6-bp153.2.3.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'icingaweb2-vendor-dompdf-2.8.6-bp153.2.3.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'icingaweb2-vendor-lessphp-2.8.6-bp153.2.3.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'icingaweb2-vendor-zf1-2.8.6-bp153.2.3.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php-Icinga-2.8.6-bp153.2.3.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'icingacli / icingaweb2 / icingaweb2-common / etc');
}
