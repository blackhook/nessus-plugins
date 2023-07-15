#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# SUSE update advisory SUSE-SU-2023:0748-1. The text itself
# is copyright (C) SUSE.
##

include('compat.inc');

if (description)
{
  script_id(172609);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/06/16");

  script_cve_id(
    "CVE-2015-20107",
    "CVE-2022-37454",
    "CVE-2022-42919",
    "CVE-2022-45061",
    "CVE-2023-24329"
  );
  script_xref(name:"SuSE", value:"SUSE-SU-2023:0748-1");
  script_xref(name:"IAVA", value:"2022-A-0467-S");
  script_xref(name:"IAVA", value:"2023-A-0061-S");
  script_xref(name:"IAVA", value:"2023-A-0283");
  script_xref(name:"IAVA", value:"2023-A-0118-S");

  script_name(english:"SUSE SLED15 / SLES15 / openSUSE 15 Security Update : python310 (SUSE-SU-2023:0748-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote SUSE Linux SLED15 / SLES15 / openSUSE 15 host has packages installed that are affected by multiple
vulnerabilities as referenced in the SUSE-SU-2023:0748-1 advisory.

  - In Python (aka CPython) up to 3.10.8, the mailcap module does not add escape characters into commands
    discovered in the system mailcap file. This may allow attackers to inject shell commands into applications
    that call mailcap.findmatch with untrusted input (if they lack validation of user-provided filenames or
    arguments). The fix is also back-ported to 3.7, 3.8, 3.9 (CVE-2015-20107)

  - The Keccak XKCP SHA-3 reference implementation before fdc6fef has an integer overflow and resultant buffer
    overflow that allows attackers to execute arbitrary code or eliminate expected cryptographic properties.
    This occurs in the sponge function interface. (CVE-2022-37454)

  - Python 3.9.x before 3.9.16 and 3.10.x before 3.10.9 on Linux allows local privilege escalation in a non-
    default configuration. The Python multiprocessing library, when used with the forkserver start method on
    Linux, allows pickles to be deserialized from any user in the same machine local network namespace, which
    in many system configurations means any user on the same machine. Pickles can execute arbitrary code.
    Thus, this allows for local user privilege escalation to the user that any forkserver process is running
    as. Setting multiprocessing.util.abstract_sockets_supported to False is a workaround. The forkserver start
    method for multiprocessing is not the default start method. This issue is Linux specific because only
    Linux supports abstract namespace sockets. CPython before 3.9 does not make use of Linux abstract
    namespace sockets by default. Support for users manually specifying an abstract namespace socket was added
    as a bugfix in 3.7.8 and 3.8.3, but users would need to make specific uncommon API calls in order to do
    that in CPython before 3.9. (CVE-2022-42919)

  - An issue was discovered in Python before 3.11.1. An unnecessary quadratic algorithm exists in one path
    when processing some inputs to the IDNA (RFC 3490) decoder, such that a crafted, unreasonably long name
    being presented to the decoder could lead to a CPU denial of service. Hostnames are often supplied by
    remote servers that could be controlled by a malicious actor; in such a scenario, they could trigger
    excessive CPU consumption on the client attempting to make use of an attacker-supplied supposed hostname.
    For example, the attack payload could be placed in the Location header of an HTTP response with status
    code 302. A fix is planned in 3.11.1, 3.10.9, 3.9.16, 3.8.16, and 3.7.16. (CVE-2022-45061)

  - An issue in the urllib.parse component of Python before v3.11 allows attackers to bypass blocklisting
    methods by supplying a URL that starts with blank characters. (CVE-2023-24329)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/831629");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1208471");
  # https://lists.suse.com/pipermail/sle-security-updates/2023-March/014044.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?3ef29eb8");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2015-20107");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-37454");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-42919");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-45061");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-24329");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:C/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2015-20107");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2022-37454");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/04/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/03/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/03/16");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libpython3_10-1_0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python310");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python310-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python310-curses");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python310-dbm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python310-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python310-idle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python310-tk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python310-tools");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:15");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
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
var os_release = get_kb_item("Host/SuSE/release");
if (isnull(os_release) || os_release !~ "^(SLED|SLES|SUSE)") audit(AUDIT_OS_NOT, "SUSE / openSUSE");
var os_ver = pregmatch(pattern: "^(SLE(S|D)\d+|SUSE([\d.]+))", string:os_release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'SUSE / openSUSE');
os_ver = os_ver[1];
if (! preg(pattern:"^(SLED15|SLES15|SUSE15\.4)$", string:os_ver)) audit(AUDIT_OS_NOT, 'SUSE SLED15 / SLES15 / openSUSE 15', 'SUSE / openSUSE (' + os_ver + ')');

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'SUSE / openSUSE (' + os_ver + ')', cpu);

var service_pack = get_kb_item("Host/SuSE/patchlevel");
if (isnull(service_pack)) service_pack = "0";
if (os_ver == "SLED15" && (! preg(pattern:"^(4)$", string:service_pack))) audit(AUDIT_OS_NOT, "SLED15 SP4", os_ver + " SP" + service_pack);
if (os_ver == "SLES15" && (! preg(pattern:"^(4)$", string:service_pack))) audit(AUDIT_OS_NOT, "SLES15 SP4", os_ver + " SP" + service_pack);

var pkgs = [
    {'reference':'libpython3_10-1_0-3.10.10-150400.4.22.1', 'sp':'4', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4', 'SLE_HPC-release-15.4', 'sle-module-python3-release-15.4', 'sled-release-15.4', 'sles-release-15.4']},
    {'reference':'libpython3_10-1_0-3.10.10-150400.4.22.1', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4', 'SLE_HPC-release-15.4', 'sle-module-python3-release-15.4', 'sled-release-15.4', 'sles-release-15.4']},
    {'reference':'python310-3.10.10-150400.4.22.1', 'sp':'4', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4', 'SLE_HPC-release-15.4', 'sle-module-python3-release-15.4', 'sled-release-15.4', 'sles-release-15.4']},
    {'reference':'python310-3.10.10-150400.4.22.1', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4', 'SLE_HPC-release-15.4', 'sle-module-python3-release-15.4', 'sled-release-15.4', 'sles-release-15.4']},
    {'reference':'python310-base-3.10.10-150400.4.22.1', 'sp':'4', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4', 'SLE_HPC-release-15.4', 'sle-module-python3-release-15.4', 'sled-release-15.4', 'sles-release-15.4']},
    {'reference':'python310-base-3.10.10-150400.4.22.1', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4', 'SLE_HPC-release-15.4', 'sle-module-python3-release-15.4', 'sled-release-15.4', 'sles-release-15.4']},
    {'reference':'python310-curses-3.10.10-150400.4.22.1', 'sp':'4', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4', 'SLE_HPC-release-15.4', 'sle-module-python3-release-15.4', 'sled-release-15.4', 'sles-release-15.4']},
    {'reference':'python310-curses-3.10.10-150400.4.22.1', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4', 'SLE_HPC-release-15.4', 'sle-module-python3-release-15.4', 'sled-release-15.4', 'sles-release-15.4']},
    {'reference':'python310-dbm-3.10.10-150400.4.22.1', 'sp':'4', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4', 'SLE_HPC-release-15.4', 'sle-module-python3-release-15.4', 'sled-release-15.4', 'sles-release-15.4']},
    {'reference':'python310-dbm-3.10.10-150400.4.22.1', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4', 'SLE_HPC-release-15.4', 'sle-module-python3-release-15.4', 'sled-release-15.4', 'sles-release-15.4']},
    {'reference':'python310-devel-3.10.10-150400.4.22.1', 'sp':'4', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4', 'SLE_HPC-release-15.4', 'sle-module-python3-release-15.4', 'sled-release-15.4', 'sles-release-15.4']},
    {'reference':'python310-devel-3.10.10-150400.4.22.1', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4', 'SLE_HPC-release-15.4', 'sle-module-python3-release-15.4', 'sled-release-15.4', 'sles-release-15.4']},
    {'reference':'python310-idle-3.10.10-150400.4.22.1', 'sp':'4', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4', 'SLE_HPC-release-15.4', 'sle-module-python3-release-15.4', 'sled-release-15.4', 'sles-release-15.4']},
    {'reference':'python310-idle-3.10.10-150400.4.22.1', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4', 'SLE_HPC-release-15.4', 'sle-module-python3-release-15.4', 'sled-release-15.4', 'sles-release-15.4']},
    {'reference':'python310-tk-3.10.10-150400.4.22.1', 'sp':'4', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4', 'SLE_HPC-release-15.4', 'sle-module-python3-release-15.4', 'sled-release-15.4', 'sles-release-15.4']},
    {'reference':'python310-tk-3.10.10-150400.4.22.1', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4', 'SLE_HPC-release-15.4', 'sle-module-python3-release-15.4', 'sled-release-15.4', 'sles-release-15.4']},
    {'reference':'python310-tools-3.10.10-150400.4.22.1', 'sp':'4', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4', 'SLE_HPC-release-15.4', 'sle-module-python3-release-15.4', 'sled-release-15.4', 'sles-release-15.4']},
    {'reference':'python310-tools-3.10.10-150400.4.22.1', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4', 'SLE_HPC-release-15.4', 'sle-module-python3-release-15.4', 'sled-release-15.4', 'sles-release-15.4']},
    {'reference':'libpython3_10-1_0-3.10.10-150400.4.22.1', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'libpython3_10-1_0-32bit-3.10.10-150400.4.22.1', 'cpu':'x86_64', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'python310-3.10.10-150400.4.22.1', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'python310-32bit-3.10.10-150400.4.22.1', 'cpu':'x86_64', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'python310-base-3.10.10-150400.4.22.1', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'python310-base-32bit-3.10.10-150400.4.22.1', 'cpu':'x86_64', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'python310-curses-3.10.10-150400.4.22.1', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'python310-dbm-3.10.10-150400.4.22.1', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'python310-devel-3.10.10-150400.4.22.1', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'python310-doc-3.10.10-150400.4.22.1', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'python310-doc-devhelp-3.10.10-150400.4.22.1', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'python310-idle-3.10.10-150400.4.22.1', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'python310-testsuite-3.10.10-150400.4.22.1', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'python310-tk-3.10.10-150400.4.22.1', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'python310-tools-3.10.10-150400.4.22.1', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']}
];

var ltss_caveat_required = FALSE;
var flag = 0;
foreach var package_array ( pkgs ) {
  var reference = NULL;
  var _release = NULL;
  var sp = NULL;
  var _cpu = NULL;
  var exists_check = NULL;
  var rpm_spec_vers_cmp = NULL;
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (!empty_or_null(package_array['release'])) _release = package_array['release'];
  if (!empty_or_null(package_array['sp'])) sp = package_array['sp'];
  if (!empty_or_null(package_array['cpu'])) _cpu = package_array['cpu'];
  if (!empty_or_null(package_array['exists_check'])) exists_check = package_array['exists_check'];
  if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
  if (reference && _release) {
    if (exists_check) {
      var check_flag = 0;
      foreach var check (exists_check) {
        if (!rpm_exists(release:_release, rpm:check)) continue;
        check_flag++;
      }
      if (!check_flag) continue;
    }
    if (rpm_check(release:_release, sp:sp, cpu:_cpu, reference:reference, rpm_spec_vers_cmp:rpm_spec_vers_cmp)) flag++;
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'libpython3_10-1_0 / libpython3_10-1_0-32bit / python310 / etc');
}
