#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Oracle Linux Security Advisory ELSA-2023-2326.
##

include('compat.inc');

if (description)
{
  script_id(175710);
  script_version("1.0");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/15");

  script_cve_id(
    "CVE-2022-39282",
    "CVE-2022-39283",
    "CVE-2022-39316",
    "CVE-2022-39317",
    "CVE-2022-39318",
    "CVE-2022-39319",
    "CVE-2022-39320",
    "CVE-2022-39347",
    "CVE-2022-41877"
  );

  script_name(english:"Oracle Linux 9 : freerdp (ELSA-2023-2326)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Oracle Linux host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Oracle Linux 9 host has packages installed that are affected by multiple vulnerabilities as referenced in the
ELSA-2023-2326 advisory.

  - FreeRDP is a free remote desktop protocol library and clients. In affected versions there is an out of
    bound read in ZGFX decoder component of FreeRDP. A malicious server can trick a FreeRDP based client to
    read out of bound data and try to decode it likely resulting in a crash. This issue has been addressed in
    the 2.9.0 release. Users are advised to upgrade. (CVE-2022-39316)

  - FreeRDP is a free remote desktop protocol library and clients. Affected versions of FreeRDP are missing
    input length validation in the `urbdrc` channel. A malicious server can trick a FreeRDP based client to
    read out of bound data and send it back to the server. This issue has been addressed in version 2.9.0 and
    all users are advised to upgrade. Users unable to upgrade should not use the `/usb` redirection switch.
    (CVE-2022-39319)

  - FreeRDP is a free remote desktop protocol library and clients. Affected versions of FreeRDP may attempt
    integer addition on too narrow types leads to allocation of a buffer too small holding the data written. A
    malicious server can trick a FreeRDP based client to read out of bound data and send it back to the
    server. This issue has been addressed in version 2.9.0 and all users are advised to upgrade. Users unable
    to upgrade should not use the `/usb` redirection switch. (CVE-2022-39320)

  - FreeRDP is a free remote desktop protocol library and clients. All FreeRDP based clients when using the
    `/video` command line switch might read uninitialized data, decode it as audio/video and display the
    result. FreeRDP based server implementations are not affected. This issue has been patched in version
    2.8.1. If you cannot upgrade do not use the `/video` switch. (CVE-2022-39283)

  - FreeRDP is a free remote desktop protocol library and clients. FreeRDP based clients on unix systems using
    `/parallel` command line switch might read uninitialized data and send it to the server the client is
    currently connected to. FreeRDP based server implementations are not affected. Please upgrade to 2.8.1
    where this issue is patched. If unable to upgrade, do not use parallel port redirection (`/parallel`
    command line switch) as a workaround. (CVE-2022-39282)

  - FreeRDP is a free remote desktop protocol library and clients. Affected versions of FreeRDP are missing
    input length validation in `drive` channel. A malicious server can trick a FreeRDP based client to read
    out of bound data and send it back to the server. This issue has been addressed in version 2.9.0 and all
    users are advised to upgrade. Users unable to upgrade should not use the drive redirection channel -
    command line options `/drive`, `+drives` or `+home-drive`. (CVE-2022-41877)

  - FreeRDP is a free remote desktop protocol library and clients. Affected versions of FreeRDP are missing
    input validation in `urbdrc` channel. A malicious server can trick a FreeRDP based client to crash with
    division by zero. This issue has been addressed in version 2.9.0. All users are advised to upgrade. Users
    unable to upgrade should not use the `/usb` redirection switch. (CVE-2022-39318)

  - FreeRDP is a free remote desktop protocol library and clients. Affected versions of FreeRDP are missing
    path canonicalization and base path check for `drive` channel. A malicious server can trick a FreeRDP
    based client to read files outside the shared directory. This issue has been addressed in version 2.9.0
    and all users are advised to upgrade. Users unable to upgrade should not use the `/drive`, `/drives` or
    `+home-drive` redirection switch. (CVE-2022-39347)

  - FreeRDP is a free remote desktop protocol library and clients. Affected versions of FreeRDP are missing a
    range check for input offset index in ZGFX decoder. A malicious server can trick a FreeRDP based client to
    read out of bound data and try to decode it. This issue has been addressed in version 2.9.0. There are no
    known workarounds for this issue. (CVE-2022-39317)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://linux.oracle.com/errata/ELSA-2023-2326.html");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-39283");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/10/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/05/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/05/15");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:9");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:freerdp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:freerdp-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:freerdp-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libwinpr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libwinpr-devel");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Oracle Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/OracleLinux", "Host/RedHat/release", "Host/RedHat/rpm-list", "Host/local_checks_enabled");

  exit(0);
}


include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item('Host/OracleLinux')) audit(AUDIT_OS_NOT, 'Oracle Linux');
var os_release = get_kb_item("Host/RedHat/release");
if (isnull(os_release) || !pregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux)", string:os_release)) audit(AUDIT_OS_NOT, 'Oracle Linux');
var os_ver = pregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux) .*release ([0-9]+(\.[0-9]+)?)", string:os_release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'Oracle Linux');
os_ver = os_ver[1];
if (! preg(pattern:"^9([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, 'Oracle Linux 9', 'Oracle Linux ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Oracle Linux', cpu);

var pkgs = [
    {'reference':'freerdp-2.4.1-5.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
    {'reference':'freerdp-2.4.1-5.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
    {'reference':'freerdp-devel-2.4.1-5.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
    {'reference':'freerdp-devel-2.4.1-5.el9', 'cpu':'i686', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
    {'reference':'freerdp-devel-2.4.1-5.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
    {'reference':'freerdp-libs-2.4.1-5.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
    {'reference':'freerdp-libs-2.4.1-5.el9', 'cpu':'i686', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
    {'reference':'freerdp-libs-2.4.1-5.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
    {'reference':'libwinpr-2.4.1-5.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
    {'reference':'libwinpr-2.4.1-5.el9', 'cpu':'i686', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
    {'reference':'libwinpr-2.4.1-5.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
    {'reference':'libwinpr-devel-2.4.1-5.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
    {'reference':'libwinpr-devel-2.4.1-5.el9', 'cpu':'i686', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
    {'reference':'libwinpr-devel-2.4.1-5.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'}
];

var flag = 0;
foreach var package_array ( pkgs ) {
  var reference = NULL;
  var _release = NULL;
  var sp = NULL;
  var _cpu = NULL;
  var el_string = NULL;
  var rpm_spec_vers_cmp = NULL;
  var epoch = NULL;
  var allowmaj = NULL;
  var exists_check = NULL;
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (!empty_or_null(package_array['release'])) _release = 'EL' + package_array['release'];
  if (!empty_or_null(package_array['sp'])) sp = package_array['sp'];
  if (!empty_or_null(package_array['cpu'])) _cpu = package_array['cpu'];
  if (!empty_or_null(package_array['el_string'])) el_string = package_array['el_string'];
  if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
  if (!empty_or_null(package_array['epoch'])) epoch = package_array['epoch'];
  if (!empty_or_null(package_array['allowmaj'])) allowmaj = package_array['allowmaj'];
  if (!empty_or_null(package_array['exists_check'])) exists_check = package_array['exists_check'];
  if (reference && _release) {
    if (exists_check) {
        if (rpm_exists(release:_release, rpm:exists_check) && rpm_check(release:_release, sp:sp, cpu:cpu, reference:reference, epoch:epoch, el_string:el_string, rpm_spec_vers_cmp:rpm_spec_vers_cmp, allowmaj:allowmaj)) flag++;
    } else {
        if (rpm_check(release:_release, sp:sp, cpu:_cpu, reference:reference, epoch:epoch, el_string:el_string, rpm_spec_vers_cmp:rpm_spec_vers_cmp, allowmaj:allowmaj)) flag++;
    }
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'freerdp / freerdp-devel / freerdp-libs / etc');
}
