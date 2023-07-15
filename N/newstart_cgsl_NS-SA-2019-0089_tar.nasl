#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

# The descriptive text and package checks in this plugin were
# extracted from ZTE advisory NS-SA-2019-0089. The text
# itself is copyright (C) ZTE, Inc.

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(127307);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/19");

  script_cve_id(
    "CVE-2006-0300",
    "CVE-2006-6097",
    "CVE-2007-4131",
    "CVE-2007-4476",
    "CVE-2010-0624",
    "CVE-2016-6321"
  );

  script_name(english:"NewStart CGSL MAIN 4.06 : tar Multiple Vulnerabilities (NS-SA-2019-0089)");

  script_set_attribute(attribute:"synopsis", value:
"The remote machine is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote NewStart CGSL host, running version MAIN 4.06, has tar packages installed that are affected by multiple
vulnerabilities:

  - Buffer overflow in tar 1.14 through 1.15.90 allows user-
    assisted attackers to cause a denial of service
    (application crash) and possibly execute code via
    unspecified vectors involving PAX extended headers.
    (CVE-2006-0300)

  - GNU tar 1.16 and 1.15.1, and possibly other versions,
    allows user-assisted attackers to overwrite arbitrary
    files via a tar file that contains a GNUTYPE_NAMES
    record with a symbolic link, which is not properly
    handled by the extract_archive function in extract.c and
    extract_mangle function in mangle.c, a variant of
    CVE-2002-1216. (CVE-2006-6097)

  - Directory traversal vulnerability in the
    contains_dot_dot function in src/names.c in GNU tar
    allows user-assisted remote attackers to overwrite
    arbitrary files via certain //.. (slash slash dot dot)
    sequences in directory symlinks in a TAR archive.
    (CVE-2007-4131)

  - Buffer overflow in the safer_name_suffix function in GNU
    tar has unspecified attack vectors and impact, resulting
    in a crashing stack. (CVE-2007-4476)

  - Heap-based buffer overflow in the rmt_read__ function in
    lib/rtapelib.c in the rmt client functionality in GNU
    tar before 1.23 and GNU cpio before 2.11 allows remote
    rmt servers to cause a denial of service (memory
    corruption) or possibly execute arbitrary code by
    sending more data than was requested, related to archive
    filenames that contain a : (colon) character.
    (CVE-2010-0624)

  - Directory traversal vulnerability in the
    safer_name_suffix function in GNU tar 1.14 through 1.29
    might allow remote attackers to bypass an intended
    protection mechanism and write to arbitrary files via
    vectors related to improper sanitization of the
    file_name parameter, aka POINTYFEATHER. (CVE-2016-6321)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/notice/NS-SA-2019-0089");
  script_set_attribute(attribute:"solution", value:
"Upgrade the vulnerable CGSL tar packages. Note that updated packages may not be available yet. Please contact ZTE for
more information.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2007-4476");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2016-6321");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(119);

  script_set_attribute(attribute:"vuln_publication_date", value:"2006/02/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/07/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/08/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"NewStart CGSL Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2019-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

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

if (release !~ "CGSL MAIN 4.06")
  audit(AUDIT_OS_NOT, 'NewStart CGSL MAIN 4.06');

if (!get_kb_item("Host/ZTE-CGSL/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "NewStart Carrier Grade Server Linux", cpu);

flag = 0;

pkgs = {
  "CGSL MAIN 4.06": [
    "tar-1.23-15.el6_8.cgslv4_6.0.1.gff7e116",
    "tar-debuginfo-1.23-15.el6_8.cgslv4_6.0.1.gff7e116"
  ]
};
pkg_list = pkgs[release];

foreach (pkg in pkg_list)
  if (rpm_check(release:"ZTE " + release, reference:pkg)) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "tar");
}
