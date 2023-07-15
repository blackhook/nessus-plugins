#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
#
# The package checks in this plugin were extracted from
# openSUSE Security Update openSUSE-SU-2022:0736-1. The text itself
# is copyright (C) SUSE.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(158630);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/03/05");

  script_cve_id(
    "CVE-2021-3778",
    "CVE-2021-3796",
    "CVE-2021-3872",
    "CVE-2021-3927",
    "CVE-2021-3928",
    "CVE-2021-3984",
    "CVE-2021-4019",
    "CVE-2021-4193",
    "CVE-2021-46059",
    "CVE-2022-0318",
    "CVE-2022-0319",
    "CVE-2022-0351",
    "CVE-2022-0361",
    "CVE-2022-0413"
  );

  script_name(english:"openSUSE 15 Security Update : vim (openSUSE-SU-2022:0736-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote SUSE Linux SUSE15 host has packages installed that are affected by multiple vulnerabilities as referenced in
the openSUSE-SU-2022:0736-1 advisory.

  - vim is vulnerable to Heap-based Buffer Overflow (CVE-2021-3778, CVE-2021-3872, CVE-2021-3927,
    CVE-2021-3984, CVE-2021-4019)

  - vim is vulnerable to Use After Free (CVE-2021-3796)

  - vim is vulnerable to Use of Uninitialized Variable (CVE-2021-3928)

  - vim is vulnerable to Out-of-bounds Read (CVE-2021-4193)

  - ** REJECT ** DO NOT USE THIS CANDIDATE NUMBER. ConsultIDs: none. Reason: This candidate was withdrawn by
    its CNA. Further investigation showed that it was not a security issue. Notes: none. (CVE-2021-46059)

  - Heap-based Buffer Overflow in vim/vim prior to 8.2. (CVE-2022-0318)

  - Out-of-bounds Read in vim/vim prior to 8.2. (CVE-2022-0319)

  - Access of Memory Location Before Start of Buffer in GitHub repository vim/vim prior to 8.2.
    (CVE-2022-0351)

  - Heap-based Buffer Overflow in GitHub repository vim/vim prior to 8.2. (CVE-2022-0361)

  - Use After Free in GitHub repository vim/vim prior to 8.2. (CVE-2022-0413)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1190533");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1190570");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1191893");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1192478");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1192481");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1193294");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1193298");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1194216");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1194556");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1195004");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1195066");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1195126");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1195202");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1195356");
  # https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/FDNZ3N5S7UGKPUUKPGOQQGPJJK3YTW37/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?7e3b18cd");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-3778");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-3796");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-3872");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-3927");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-3928");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-3984");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-4019");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-4193");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-46059");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-0318");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-0319");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-0351");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-0361");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-0413");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-0318");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/09/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/03/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/03/05");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gvim");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:vim");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:vim-data");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:vim-data-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:vim-small");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.3");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"SuSE Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/SuSE/release", "Host/SuSE/rpm-list");

  exit(0);
}


include('audit.inc');
include('global_settings.inc');
include('misc_func.inc');
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
    {'reference':'gvim-8.0.1568-5.17.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'vim-8.0.1568-5.17.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'vim-data-8.0.1568-5.17.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'vim-data-common-8.0.1568-5.17.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'vim-small-8.0.1568-5.17.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE}
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
      severity   : SECURITY_HOLE,
      extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'gvim / vim / vim-data / vim-data-common / vim-small');
}
