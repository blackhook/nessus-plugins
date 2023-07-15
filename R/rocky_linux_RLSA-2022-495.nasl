#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
#
# The package checks in this plugin were extracted from
# Rocky Linux Security Advisory RLSA-2022:495.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(157863);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/27");

  script_cve_id("CVE-2022-219862");
  script_xref(name:"RLSA", value:"2022:495");
  script_xref(name:"IAVA", value:"2022-A-0078-S");

  script_name(english:"Rocky Linux 8 : .NET 5.0 (RLSA-2022:495)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Rocky Linux host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The remote Rocky Linux 8 host has packages installed that are affected by a vulnerability as referenced in the
RLSA-2022:495 advisory.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://errata.rockylinux.org/RLSA-2022:495");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2051490");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-219862");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/02/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/02/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/02/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:aspnetcore-runtime-5.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:aspnetcore-runtime-6.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:aspnetcore-targeting-pack-5.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:aspnetcore-targeting-pack-6.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:dotnet");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:dotnet-apphost-pack-5.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:dotnet-apphost-pack-5.0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:dotnet-apphost-pack-6.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:dotnet-apphost-pack-6.0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:dotnet-host");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:dotnet-host-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:dotnet-hostfxr-5.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:dotnet-hostfxr-5.0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:dotnet-hostfxr-6.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:dotnet-hostfxr-6.0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:dotnet-runtime-5.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:dotnet-runtime-5.0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:dotnet-runtime-6.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:dotnet-runtime-6.0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:dotnet-sdk-5.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:dotnet-sdk-5.0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:dotnet-sdk-5.0-source-built-artifacts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:dotnet-sdk-6.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:dotnet-sdk-6.0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:dotnet-targeting-pack-5.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:dotnet-targeting-pack-6.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:dotnet-templates-5.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:dotnet-templates-6.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:dotnet5.0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:dotnet5.0-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:dotnet6.0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:netstandard-targeting-pack-2.1");
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
    {'reference':'aspnetcore-runtime-5.0-5.0.14-1.el8_5', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'aspnetcore-runtime-6.0-6.0.2-1.el8_5', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'aspnetcore-runtime-6.0-6.0.2-1.el8_5', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'aspnetcore-targeting-pack-5.0-5.0.14-1.el8_5', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'aspnetcore-targeting-pack-6.0-6.0.2-1.el8_5', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'aspnetcore-targeting-pack-6.0-6.0.2-1.el8_5', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'dotnet-6.0.102-1.el8_5', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'dotnet-apphost-pack-5.0-5.0.14-1.el8_5', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'dotnet-apphost-pack-5.0-debuginfo-5.0.14-1.el8_5', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'dotnet-apphost-pack-6.0-6.0.2-1.el8_5', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'dotnet-apphost-pack-6.0-6.0.2-1.el8_5', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'dotnet-apphost-pack-6.0-debuginfo-6.0.2-1.el8_5', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'dotnet-apphost-pack-6.0-debuginfo-6.0.2-1.el8_5', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'dotnet-host-6.0.2-1.el8_5', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'dotnet-host-6.0.2-1.el8_5', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'dotnet-host-debuginfo-6.0.2-1.el8_5', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'dotnet-host-debuginfo-6.0.2-1.el8_5', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'dotnet-hostfxr-5.0-5.0.14-1.el8_5', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'dotnet-hostfxr-5.0-debuginfo-5.0.14-1.el8_5', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'dotnet-hostfxr-6.0-6.0.2-1.el8_5', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'dotnet-hostfxr-6.0-6.0.2-1.el8_5', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'dotnet-hostfxr-6.0-debuginfo-6.0.2-1.el8_5', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'dotnet-hostfxr-6.0-debuginfo-6.0.2-1.el8_5', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'dotnet-runtime-5.0-5.0.14-1.el8_5', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'dotnet-runtime-5.0-debuginfo-5.0.14-1.el8_5', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'dotnet-runtime-6.0-6.0.2-1.el8_5', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'dotnet-runtime-6.0-6.0.2-1.el8_5', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'dotnet-runtime-6.0-debuginfo-6.0.2-1.el8_5', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'dotnet-runtime-6.0-debuginfo-6.0.2-1.el8_5', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'dotnet-sdk-5.0-5.0.211-1.el8_5', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'dotnet-sdk-5.0-debuginfo-5.0.211-1.el8_5', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'dotnet-sdk-5.0-source-built-artifacts-5.0.211-1.el8_5', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'dotnet-sdk-6.0-6.0.102-1.el8_5', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'dotnet-sdk-6.0-6.0.102-1.el8_5', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'dotnet-sdk-6.0-debuginfo-6.0.102-1.el8_5', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'dotnet-sdk-6.0-debuginfo-6.0.102-1.el8_5', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'dotnet-targeting-pack-5.0-5.0.14-1.el8_5', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'dotnet-targeting-pack-6.0-6.0.2-1.el8_5', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'dotnet-targeting-pack-6.0-6.0.2-1.el8_5', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'dotnet-templates-5.0-5.0.211-1.el8_5', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'dotnet-templates-6.0-6.0.102-1.el8_5', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'dotnet-templates-6.0-6.0.102-1.el8_5', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'dotnet5.0-debuginfo-5.0.211-1.el8_5', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'dotnet5.0-debugsource-5.0.211-1.el8_5', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'dotnet6.0-debuginfo-6.0.102-1.el8_5', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'dotnet6.0-debuginfo-6.0.102-1.el8_5', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'netstandard-targeting-pack-2.1-6.0.102-1.el8_5', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'netstandard-targeting-pack-2.1-6.0.102-1.el8_5', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'aspnetcore-runtime-5.0 / aspnetcore-runtime-6.0 / etc');
}
