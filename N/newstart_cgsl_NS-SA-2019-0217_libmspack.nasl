#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

# The descriptive text and package checks in this plugin were
# extracted from ZTE advisory NS-SA-2019-0217. The text
# itself is copyright (C) ZTE, Inc.

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(131413);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id(
    "CVE-2018-14679",
    "CVE-2018-14680",
    "CVE-2018-14681",
    "CVE-2018-14682",
    "CVE-2018-18584",
    "CVE-2018-18585"
  );

  script_name(english:"NewStart CGSL CORE 5.04 / MAIN 5.04 : libmspack Multiple Vulnerabilities (NS-SA-2019-0217)");

  script_set_attribute(attribute:"synopsis", value:
"The remote machine is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote NewStart CGSL host, running version CORE 5.04 / MAIN 5.04, has libmspack packages installed that are affected
by multiple vulnerabilities:

  - An issue was discovered in mspack/chmd.c in libmspack
    before 0.7alpha. There is an off-by-one error in the CHM
    PMGI/PMGL chunk number validity checks, which could lead
    to denial of service (uninitialized data dereference and
    application crash). (CVE-2018-14679)

  - In mspack/cab.h in libmspack before 0.8alpha and
    cabextract before 1.8, the CAB block input buffer is one
    byte too small for the maximal Quantum block, leading to
    an out-of-bounds write. (CVE-2018-18584)

  - chmd_read_headers in mspack/chmd.c in libmspack before
    0.8alpha accepts a filename that has '\0' as its first
    or second character (such as the /\0 name).
    (CVE-2018-18585)

  - An issue was discovered in mspack/chmd.c in libmspack
    before 0.7alpha. It does not reject blank CHM filenames.
    (CVE-2018-14680)

  - An issue was discovered in mspack/chmd.c in libmspack
    before 0.7alpha. There is an off-by-one error in the
    TOLOWER() macro for CHM decompression. (CVE-2018-14682)

  - An issue was discovered in kwajd_read_headers in
    mspack/kwajd.c in libmspack before 0.7alpha. Bad KWAJ
    file header extensions could cause a one or two byte
    overwrite. (CVE-2018-14681)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/notice/NS-SA-2019-0217");
  script_set_attribute(attribute:"solution", value:
"Upgrade the vulnerable CGSL libmspack packages. Note that updated packages may not be available yet. Please contact ZTE
for more information.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-14682");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/07/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/11/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/12/02");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"NewStart CGSL Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2019-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/ZTE-CGSL/release", "Host/ZTE-CGSL/rpm-list", "Host/cpu");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

release = get_kb_item("Host/ZTE-CGSL/release");
if (isnull(release) || release !~ "^CGSL (MAIN|CORE)") audit(AUDIT_OS_NOT, "NewStart Carrier Grade Server Linux");

if (release !~ "CGSL CORE 5.04" &&
    release !~ "CGSL MAIN 5.04")
  audit(AUDIT_OS_NOT, 'NewStart CGSL CORE 5.04 / NewStart CGSL MAIN 5.04');

if (!get_kb_item("Host/ZTE-CGSL/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "NewStart Carrier Grade Server Linux", cpu);

flag = 0;

pkgs = {
  "CGSL CORE 5.04": [
    "libmspack-0.5-0.7.alpha.el7",
    "libmspack-debuginfo-0.5-0.7.alpha.el7",
    "libmspack-devel-0.5-0.7.alpha.el7"
  ],
  "CGSL MAIN 5.04": [
    "libmspack-0.5-0.7.alpha.el7",
    "libmspack-debuginfo-0.5-0.7.alpha.el7",
    "libmspack-devel-0.5-0.7.alpha.el7"
  ]
};
pkg_list = pkgs[release];

foreach (pkg in pkg_list)
  if (rpm_check(release:"ZTE " + release, reference:pkg)) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libmspack");
}
