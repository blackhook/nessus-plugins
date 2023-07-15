##
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Oracle Linux Security Advisory ELSA-2021-0507.
##

include('compat.inc');

if (description)
{
  script_id(146639);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/05/11");

  script_cve_id("CVE-2020-17525");

  script_name(english:"Oracle Linux 8 : subversion:1.10 (ELSA-2021-0507)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Oracle Linux host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The remote Oracle Linux 8 host has packages installed that are affected by a vulnerability as referenced in the
ELSA-2021-0507 advisory.

  - Subversion's mod_authz_svn module will crash if the server is using in-repository authz rules with the
    AuthzSVNReposRelativeAccessFile option and a client sends a request for a non-existing repository URL.
    This can lead to disruption for users of the service. This issue was fixed in mod_dav_svn+mod_authz_svn
    servers 1.14.1 and mod_dav_svn+mod_authz_svn servers 1.10.7 (CVE-2020-17525)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://linux.oracle.com/errata/ELSA-2021-0507.html");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-17525");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/02/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/02/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/02/20");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libserf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:mod_dav_svn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:subversion");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:subversion-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:subversion-gnome");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:subversion-javahl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:subversion-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:subversion-perl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:subversion-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:utf8proc");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Oracle Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/OracleLinux", "Host/RedHat/release", "Host/RedHat/rpm-list", "Host/local_checks_enabled");

  exit(0);
}


include('audit.inc');
include('global_settings.inc');
include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item('Host/OracleLinux')) audit(AUDIT_OS_NOT, 'Oracle Linux');
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || !pregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux)", string:release)) audit(AUDIT_OS_NOT, 'Oracle Linux');
os_ver = pregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux) .*release ([0-9]+(\.[0-9]+)?)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'Oracle Linux');
os_ver = os_ver[1];
if (! preg(pattern:"^8([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, 'Oracle Linux 8', 'Oracle Linux ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Oracle Linux', cpu);

module_ver = get_kb_item('Host/RedHat/appstream/subversion');
if (isnull(module_ver)) audit(AUDIT_PACKAGE_NOT_INSTALLED, 'Module subversion:1.10');
if ('1.10' >!< module_ver) audit(AUDIT_PACKAGE_NOT_AFFECTED, 'Module subversion:' + module_ver);

appstreams = {
    'subversion:1.10': [
      {'reference':'libserf-1.3.9-9.module+el8.3.0+7671+a87d5147', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libserf-1.3.9-9.module+el8.3.0+7671+a87d5147', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'mod_dav_svn-1.10.2-4.module+el8.3.0+9645+c2a98c55', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'mod_dav_svn-1.10.2-4.module+el8.3.0+9645+c2a98c55', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'subversion-1.10.2-4.module+el8.3.0+9645+c2a98c55', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'subversion-1.10.2-4.module+el8.3.0+9645+c2a98c55', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'subversion-devel-1.10.2-4.module+el8.3.0+9645+c2a98c55', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'subversion-devel-1.10.2-4.module+el8.3.0+9645+c2a98c55', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'subversion-gnome-1.10.2-4.module+el8.3.0+9645+c2a98c55', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'subversion-gnome-1.10.2-4.module+el8.3.0+9645+c2a98c55', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'subversion-javahl-1.10.2-4.module+el8.3.0+9645+c2a98c55', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'subversion-libs-1.10.2-4.module+el8.3.0+9645+c2a98c55', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'subversion-libs-1.10.2-4.module+el8.3.0+9645+c2a98c55', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'subversion-perl-1.10.2-4.module+el8.3.0+9645+c2a98c55', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'subversion-perl-1.10.2-4.module+el8.3.0+9645+c2a98c55', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'subversion-tools-1.10.2-4.module+el8.3.0+9645+c2a98c55', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'subversion-tools-1.10.2-4.module+el8.3.0+9645+c2a98c55', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'utf8proc-2.1.1-5.module+el8.3.0+7671+a87d5147', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'utf8proc-2.1.1-5.module+el8.3.0+7671+a87d5147', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE}
    ]
};

flag = 0;
appstreams_found = 0;
foreach module (keys(appstreams)) {
  appstream = NULL;
  appstream_name = NULL;
  appstream_version = NULL;
  appstream_split = split(module, sep:':', keep:FALSE);
  if (!empty_or_null(appstream_split)) {
    appstream_name = appstream_split[0];
    appstream_version = appstream_split[1];
    if (!empty_or_null(appstream_name)) appstream = get_one_kb_item('Host/RedHat/appstream/' + appstream_name);
  }
  if (!empty_or_null(appstream) && appstream_version == appstream || appstream_name == 'all') {
    appstreams_found++;
    foreach package_array ( appstreams[module] ) {
      reference = NULL;
      release = NULL;
      sp = NULL;
      cpu = NULL;
      el_string = NULL;
      rpm_spec_vers_cmp = NULL;
      epoch = NULL;
      allowmaj = NULL;
      if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
      if (!empty_or_null(package_array['release'])) release = 'EL' + package_array['release'];
      if (!empty_or_null(package_array['sp'])) sp = package_array['sp'];
      if (!empty_or_null(package_array['cpu'])) cpu = package_array['cpu'];
      if (!empty_or_null(package_array['el_string'])) el_string = package_array['el_string'];
      if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
      if (!empty_or_null(package_array['epoch'])) epoch = package_array['epoch'];
      if (!empty_or_null(package_array['allowmaj'])) allowmaj = package_array['allowmaj'];
      if (reference && release) {
        if (rpm_check(release:release, sp:sp, cpu:cpu, reference:reference, epoch:epoch, el_string:el_string, rpm_spec_vers_cmp:rpm_spec_vers_cmp, allowmaj:allowmaj)) flag++;
      }
    }
  }
}

if (!appstreams_found) audit(AUDIT_PACKAGE_NOT_INSTALLED, 'Module subversion:1.10');

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'libserf / mod_dav_svn / subversion / etc');
}
