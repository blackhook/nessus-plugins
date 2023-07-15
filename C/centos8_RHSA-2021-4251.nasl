#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
#
# The package checks in this plugin were extracted from
# Red Hat Security Advisory RHSA-2021:4251. The text
# itself is copyright (C) Red Hat, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(155186);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/05");

  script_cve_id(
    "CVE-2018-5727",
    "CVE-2018-5785",
    "CVE-2018-20845",
    "CVE-2018-20847",
    "CVE-2019-12973",
    "CVE-2020-15389",
    "CVE-2020-27814",
    "CVE-2020-27823",
    "CVE-2020-27824",
    "CVE-2020-27842",
    "CVE-2020-27843",
    "CVE-2020-27845",
    "CVE-2021-3575",
    "CVE-2021-29338"
  );
  script_xref(name:"RHSA", value:"2021:4251");
  script_xref(name:"CEA-ID", value:"CEA-2021-0025");

  script_name(english:"CentOS 8 : openjpeg2 (CESA-2021:4251)");

  script_set_attribute(attribute:"synopsis", value:
"The remote CentOS host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote CentOS Linux 8 host has packages installed that are affected by multiple vulnerabilities as referenced in the
CESA-2021:4251 advisory.

  - openjpeg: division-by-zero in functions pi_next_pcrl, pi_next_cprl, and pi_next_rpcl in openmj2/pi.c
    (CVE-2018-20845)

  - openjpeg: integer overflow in function opj_get_encoding_parameters in openjp2/pi.c (CVE-2018-20847)

  - openjpeg: integer overflow in opj_t1_encode_cblks in src/lib/openjp2/t1.c (CVE-2018-5727)

  - openjpeg: integer overflow in opj_j2k_setup_encoder function in openjp2/j2k.c (CVE-2018-5785)

  - openjpeg: denial of service in function opj_t1_encode_cblks in openjp2/t1.c (CVE-2019-12973)

  - openjpeg: use-after-free and double-free via a mix of valid and invalid files in a directory operated on
    by the decompressor (CVE-2020-15389)

  - openjpeg: heap-buffer-overflow in lib/openjp2/mqc.c could result in DoS (CVE-2020-27814)

  - openjpeg: heap-buffer-overflow write in opj_tcd_dc_level_shift_encode() (CVE-2020-27823)

  - openjpeg: global-buffer-overflow read in opj_dwt_calc_explicit_stepsizes() (CVE-2020-27824)

  - openjpeg: null pointer dereference in opj_tgt_reset function in lib/openjp2/tgt.c (CVE-2020-27842)

  - openjpeg: out-of-bounds read in opj_t2_encode_packet function in openjp2/t2.c (CVE-2020-27843)

  - openjpeg: heap-based buffer overflow in functions opj_pi_next_rlcp, opj_pi_next_rpcl and opj_pi_next_lrcp
    in openjp2/pi.c (CVE-2020-27845)

  - openjpeg: out-of-bounds write due to an integer overflow in opj_compress.c (CVE-2021-29338)

  - openjpeg: heap-buffer-overflow in color.c may lead to DoS or arbitrary code execution (CVE-2021-3575)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2021:4251");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-3575");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2018-20847");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/01/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/11/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/11/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:8-stream");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openjpeg2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openjpeg2-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openjpeg2-devel-docs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openjpeg2-tools");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CentOS Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/CentOS/release", "Host/CentOS/rpm-list", "Host/cpu");

  exit(0);
}


include('audit.inc');
include('global_settings.inc');
include('misc_func.inc');
include('rpm.inc');
include('rhel.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var release = get_kb_item('Host/CentOS/release');
if (isnull(release) || 'CentOS' >!< release) audit(AUDIT_OS_NOT, 'CentOS');
var os_ver = pregmatch(pattern: "CentOS(?: Stream)?(?: Linux)? release ([0-9]+)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'CentOS');
var os_ver = os_ver[1];
if ('CentOS Stream' >!< release) audit(AUDIT_OS_NOT, 'CentOS 8-Stream');
if (!rhel_check_release(operator: 'ge', os_version: os_ver, rhel_version: '8')) audit(AUDIT_OS_NOT, 'CentOS 8.x', 'CentOS ' + os_ver);

if (!get_kb_item('Host/CentOS/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'CentOS', cpu);

var pkgs = [
    {'reference':'openjpeg2-2.4.0-4.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'openjpeg2-2.4.0-4.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'openjpeg2-devel-2.4.0-4.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'openjpeg2-devel-2.4.0-4.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'openjpeg2-devel-docs-2.4.0-4.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'openjpeg2-devel-docs-2.4.0-4.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'openjpeg2-tools-2.4.0-4.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'openjpeg2-tools-2.4.0-4.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE}
];

var flag = 0;
foreach package_array ( pkgs ) {
  var reference = NULL;
  var release = NULL;
  var sp = NULL;
  var cpu = NULL;
  var el_string = NULL;
  var rpm_spec_vers_cmp = NULL;
  var epoch = NULL;
  var allowmaj = NULL;
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (!empty_or_null(package_array['release'])) release = 'CentOS-' + package_array['release'];
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'openjpeg2 / openjpeg2-devel / openjpeg2-devel-docs / openjpeg2-tools');
}
