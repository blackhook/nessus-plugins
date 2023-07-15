##
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Oracle Linux Security Advisory ELSA-2020-0579.
##

include('compat.inc');

if (description)
{
  script_id(140035);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/05/11");

  script_cve_id(
    "CVE-2019-15604",
    "CVE-2019-15605",
    "CVE-2019-15606",
    "CVE-2019-16775",
    "CVE-2019-16776",
    "CVE-2019-16777"
  );

  script_name(english:"Oracle Linux 8 : nodejs:10 (ELSA-2020-0579)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Oracle Linux host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Oracle Linux 8 host has packages installed that are affected by multiple vulnerabilities as referenced in the
ELSA-2020-0579 advisory.

  - Including trailing white space in HTTP header values in Nodejs 10, 12, and 13 causes bypass of
    authorization based on header value comparisons (CVE-2019-15606)

  - Versions of the npm CLI prior to 6.13.3 are vulnerable to an Arbitrary File Write. It is possible for
    packages to create symlinks to files outside of thenode_modules folder through the bin field upon
    installation. A properly constructed entry in the package.json bin field would allow a package publisher
    to create a symlink pointing to arbitrary files on a user's system when the package is installed. This
    behavior is still possible through install scripts. This vulnerability bypasses a user using the --ignore-
    scripts install option. (CVE-2019-16775)

  - Versions of the npm CLI prior to 6.13.4 are vulnerable to an Arbitrary File Overwrite. It fails to prevent
    existing globally-installed binaries to be overwritten by other package installations. For example, if a
    package was installed globally and created a serve binary, any subsequent installs of packages that also
    create a serve binary would overwrite the previous serve binary. This behavior is still allowed in local
    installations and also through install scripts. This vulnerability bypasses a user using the --ignore-
    scripts install option. (CVE-2019-16777)

  - Improper Certificate Validation in Node.js 10, 12, and 13 causes the process to abort when sending a
    crafted X.509 certificate (CVE-2019-15604)

  - HTTP request smuggling in Node.js 10, 12, and 13 causes malicious payload delivery when transfer-encoding
    is malformed (CVE-2019-15605)

  - Versions of the npm CLI prior to 6.13.3 are vulnerable to an Arbitrary File Write. It fails to prevent
    access to folders outside of the intended node_modules folder through the bin field. A properly
    constructed entry in the package.json bin field would allow a package publisher to modify and/or gain
    access to arbitrary files on a user's system when the package is installed. This behavior is still
    possible through install scripts. This vulnerability bypasses a user using the --ignore-scripts install
    option. (CVE-2019-16776)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://linux.oracle.com/errata/ELSA-2020-0579.html");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-15606");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/12/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/02/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/08/28");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:nodejs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:nodejs-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:nodejs-docs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:nodejs-nodemon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:nodejs-packaging");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:npm");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Oracle Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2020-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

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

module_ver = get_kb_item('Host/RedHat/appstream/nodejs');
if (isnull(module_ver)) audit(AUDIT_PACKAGE_NOT_INSTALLED, 'Module nodejs:10');
if ('10' >!< module_ver) audit(AUDIT_PACKAGE_NOT_AFFECTED, 'Module nodejs:' + module_ver);

appstreams = {
    'nodejs:10': [
      {'reference':'nodejs-10.19.0-1.module+el8.1.0+5552+3cab52c0', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'nodejs-10.19.0-1.module+el8.1.0+5552+3cab52c0', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'nodejs-devel-10.19.0-1.module+el8.1.0+5552+3cab52c0', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'nodejs-devel-10.19.0-1.module+el8.1.0+5552+3cab52c0', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'nodejs-docs-10.19.0-1.module+el8.1.0+5552+3cab52c0', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'nodejs-nodemon-1.18.3-1.module+el8.1.0+5392+4d6b561f', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'nodejs-packaging-17-3.module+el8.1.0+5392+4d6b561f', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'npm-6.13.4-1.10.19.0.1.module+el8.1.0+5552+3cab52c0', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'npm-6.13.4-1.10.19.0.1.module+el8.1.0+5552+3cab52c0', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'}
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

if (!appstreams_found) audit(AUDIT_PACKAGE_NOT_INSTALLED, 'Module nodejs:10');

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'nodejs / nodejs-devel / nodejs-docs / etc');
}
