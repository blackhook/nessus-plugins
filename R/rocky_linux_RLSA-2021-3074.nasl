#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
#
# The package checks in this plugin were extracted from
# Rocky Linux Security Advisory RLSA-2021:3074.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(157766);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/06");

  script_cve_id("CVE-2021-23362", "CVE-2021-27290");
  script_xref(name:"RLSA", value:"2021:3074");
  script_xref(name:"IAVB", value:"2021-B-0041-S");
  script_xref(name:"IAVA", value:"2021-A-0481-S");

  script_name(english:"Rocky Linux 8 : nodejs:14 (RLSA-2021:3074)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Rocky Linux host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Rocky Linux 8 host has packages installed that are affected by multiple vulnerabilities as referenced in the
RLSA-2021:3074 advisory.

  - The package hosted-git-info before 3.0.8 are vulnerable to Regular Expression Denial of Service (ReDoS)
    via regular expression shortcutMatch in the fromUrl function in index.js. The affected regular expression
    exhibits polynomial worst-case time complexity. (CVE-2021-23362)

  - ssri 5.2.2-8.0.0, fixed in 8.0.1, processes SRIs using a regular expression which is vulnerable to a
    denial of service. Malicious SRIs could take an extremely long time to process, leading to denial of
    service. This issue only affects consumers using the strict option. (CVE-2021-27290)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://errata.rockylinux.org/RLSA-2021:3074");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1941471");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1943208");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1979338");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-23362");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2021-27290");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/03/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/08/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/02/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:nodejs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:nodejs-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:nodejs-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:nodejs-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:nodejs-docs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:nodejs-full-i18n");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:nodejs-nodemon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:nodejs-packaging");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:npm");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:rocky:linux:8");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Rocky Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/RockyLinux/release", "Host/RockyLinux/rpm-list", "Host/cpu");

  exit(0);
}


include('audit.inc');
include('global_settings.inc');
include('misc_func.inc');
include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var release = get_kb_item('Host/RockyLinux/release');
if (isnull(release) || 'Rocky Linux' >!< release) audit(AUDIT_OS_NOT, 'Rocky Linux');
var os_ver = pregmatch(pattern: "Rocky(?: Linux)? release ([0-9]+(\.[0-9]+)?)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'Rocky Linux');
var os_ver = os_ver[1];
if (! preg(pattern:"^8([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, 'Rocky Linux 8.x', 'Rocky Linux ' + os_ver);

if (!get_kb_item('Host/RockyLinux/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Rocky Linux', cpu);

var pkgs = [
    {'reference':'nodejs-12.22.3-2.module+el8.4.0+638+5344c6f7', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'nodejs-12'},
    {'reference':'nodejs-12.22.3-2.module+el8.4.0+638+5344c6f7', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'nodejs-12'},
    {'reference':'nodejs-14.17.3-2.module+el8.4.0+639+18660d0d', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'nodejs-14'},
    {'reference':'nodejs-14.17.3-2.module+el8.4.0+639+18660d0d', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'nodejs-14'},
    {'reference':'nodejs-debuginfo-12.22.3-2.module+el8.4.0+638+5344c6f7', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'nodejs-debuginfo-12'},
    {'reference':'nodejs-debuginfo-12.22.3-2.module+el8.4.0+638+5344c6f7', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'nodejs-debuginfo-12'},
    {'reference':'nodejs-debuginfo-14.17.3-2.module+el8.4.0+639+18660d0d', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'nodejs-debuginfo-14'},
    {'reference':'nodejs-debuginfo-14.17.3-2.module+el8.4.0+639+18660d0d', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'nodejs-debuginfo-14'},
    {'reference':'nodejs-debugsource-12.22.3-2.module+el8.4.0+638+5344c6f7', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'nodejs-debugsource-12'},
    {'reference':'nodejs-debugsource-12.22.3-2.module+el8.4.0+638+5344c6f7', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'nodejs-debugsource-12'},
    {'reference':'nodejs-debugsource-14.17.3-2.module+el8.4.0+639+18660d0d', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'nodejs-debugsource-14'},
    {'reference':'nodejs-debugsource-14.17.3-2.module+el8.4.0+639+18660d0d', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'nodejs-debugsource-14'},
    {'reference':'nodejs-devel-12.22.3-2.module+el8.4.0+638+5344c6f7', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'nodejs-devel-12'},
    {'reference':'nodejs-devel-12.22.3-2.module+el8.4.0+638+5344c6f7', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'nodejs-devel-12'},
    {'reference':'nodejs-devel-14.17.3-2.module+el8.4.0+639+18660d0d', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'nodejs-devel-14'},
    {'reference':'nodejs-devel-14.17.3-2.module+el8.4.0+639+18660d0d', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'nodejs-devel-14'},
    {'reference':'nodejs-docs-12.22.3-2.module+el8.4.0+638+5344c6f7', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'nodejs-docs-12'},
    {'reference':'nodejs-docs-14.17.3-2.module+el8.4.0+639+18660d0d', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'nodejs-docs-14'},
    {'reference':'nodejs-full-i18n-12.22.3-2.module+el8.4.0+638+5344c6f7', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'nodejs-full-i18n-12'},
    {'reference':'nodejs-full-i18n-12.22.3-2.module+el8.4.0+638+5344c6f7', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'nodejs-full-i18n-12'},
    {'reference':'nodejs-full-i18n-14.17.3-2.module+el8.4.0+639+18660d0d', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'nodejs-full-i18n-14'},
    {'reference':'nodejs-full-i18n-14.17.3-2.module+el8.4.0+639+18660d0d', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'nodejs-full-i18n-14'},
    {'reference':'nodejs-nodemon-2.0.3-1.module+el8.4.0+638+5344c6f7', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'nodejs-packaging-17-3.module+el8.3.0+101+f84c7154', 'release':'8', 'el_string':'el8.3.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'nodejs-packaging-17'},
    {'reference':'nodejs-packaging-23-3.module+el8.3.0+100+234774f7', 'release':'8', 'el_string':'el8.3.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'nodejs-packaging-23'},
    {'reference':'npm-6.14.13-1.12.22.3.2.module+el8.4.0+638+5344c6f7', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'npm-6.14.13-1.12.22.3.2.module+el8.4.0+638+5344c6f7', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'npm-6.14.13-1.14.17.3.2.module+el8.4.0+639+18660d0d', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'npm-6.14.13-1.14.17.3.2.module+el8.4.0+639+18660d0d', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE}
];

var flag = 0;
foreach var package_array ( pkgs ) {
  var reference = NULL;
  var release = NULL;
  var sp = NULL;
  var cpu = NULL;
  var el_string = NULL;
  var rpm_spec_vers_cmp = NULL;
  var epoch = NULL;
  var allowmaj = NULL;
  var exists_check = NULL;
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (!empty_or_null(package_array['release'])) release = 'Rocky-' + package_array['release'];
  if (!empty_or_null(package_array['sp'])) sp = package_array['sp'];
  if (!empty_or_null(package_array['cpu'])) cpu = package_array['cpu'];
  if (!empty_or_null(package_array['el_string'])) el_string = package_array['el_string'];
  if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
  if (!empty_or_null(package_array['epoch'])) epoch = package_array['epoch'];
  if (!empty_or_null(package_array['allowmaj'])) allowmaj = package_array['allowmaj'];
  if (!empty_or_null(package_array['exists_check'])) exists_check = package_array['exists_check'];
  if (reference && release && (!exists_check || rpm_exists(release:release, rpm:exists_check))) {
    if (rpm_check(release:release, sp:sp, cpu:cpu, reference:reference, epoch:epoch, el_string:el_string, rpm_spec_vers_cmp:rpm_spec_vers_cmp, allowmaj:allowmaj)) flag++;
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'nodejs / nodejs-debuginfo / nodejs-debugsource / nodejs-devel / etc');
}
