##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# openSUSE Security Update openSUSE-SU-2022:1064-1. The text itself
# is copyright (C) SUSE.
##

include('compat.inc');

if (description)
{
  script_id(159392);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/01/04");

  script_cve_id("CVE-2021-33430", "CVE-2021-41495", "CVE-2021-41496");

  script_name(english:"openSUSE 15 Security Update : python2-numpy (openSUSE-SU-2022:1064-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote SUSE Linux SUSE15 host has packages installed that are affected by multiple vulnerabilities as referenced in
the openSUSE-SU-2022:1064-1 advisory.

  - ** DISPUTED ** A Buffer Overflow vulnerability exists in NumPy 1.9.x in the PyArray_NewFromDescr_int
    function of ctors.c when specifying arrays of large dimensions (over 32) from Python code, which could let
    a malicious user cause a Denial of Service. NOTE: The vendor does not agree this is a vulneraility; In
    (very limited) circumstances a user may be able provoke the buffer overflow, the user is most likely
    already privileged to at least provoke denial of service by exhausting memory. Triggering this further
    requires the use of uncommon API (complicated structured dtypes), which is very unlikely to be available
    to an unprivileged user. (CVE-2021-33430)

  - ** DISPUTED ** Null Pointer Dereference vulnerability exists in numpy.sort in NumPy < and 1.19 in the
    PyArray_DescrNew function due to missing return-value validation, which allows attackers to conduct DoS
    attacks by repetitively creating sort arrays. NOTE: While correct that validation is missing, an error can
    only occur due to an exhaustion of memory. If the user can exhaust memory, they are already privileged.
    Further, it should be practically impossible to construct an attack which can target the memory exhaustion
    to occur at exactly this place. (CVE-2021-41495)

  - ** DISPUTED ** Buffer overflow in the array_from_pyobj function of fortranobject.c in NumPy < 1.19, which
    allows attackers to conduct a Denial of Service attacks by carefully constructing an array with negative
    values. NOTE: The vendor does not agree this is a vulnerability; the negative dimensions can only be
    created by an already privileged user (or internally). (CVE-2021-41496)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1193907");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1193911");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1193913");
  # https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/IVU5XH7TX2TXVVZCKS7DIEBNEJKYZTSK/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b22d36b4");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-33430");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-41495");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-41496");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-41495");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2021-41496");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/12/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/09/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/04/01");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python2-numpy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python2-numpy-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python2-numpy-gnu-hpc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python2-numpy-gnu-hpc-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python2-numpy_1_16_5-gnu-hpc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python2-numpy_1_16_5-gnu-hpc-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.3");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"SuSE Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
    {'reference':'python2-numpy-1.16.5-150200.3.5.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python2-numpy-devel-1.16.5-150200.3.5.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python2-numpy-gnu-hpc-1.16.5-150200.3.5.1', 'cpu':'aarch64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python2-numpy-gnu-hpc-1.16.5-150200.3.5.1', 'cpu':'x86_64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python2-numpy-gnu-hpc-devel-1.16.5-150200.3.5.1', 'cpu':'aarch64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python2-numpy-gnu-hpc-devel-1.16.5-150200.3.5.1', 'cpu':'x86_64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python2-numpy_1_16_5-gnu-hpc-1.16.5-150200.3.5.1', 'cpu':'aarch64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python2-numpy_1_16_5-gnu-hpc-1.16.5-150200.3.5.1', 'cpu':'x86_64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python2-numpy_1_16_5-gnu-hpc-devel-1.16.5-150200.3.5.1', 'cpu':'aarch64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python2-numpy_1_16_5-gnu-hpc-devel-1.16.5-150200.3.5.1', 'cpu':'x86_64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE}
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
      severity   : SECURITY_NOTE,
      extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'python2-numpy / python2-numpy-devel / python2-numpy-gnu-hpc / etc');
}
