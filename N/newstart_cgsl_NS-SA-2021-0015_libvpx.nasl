##
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from ZTE advisory NS-SA-2021-0015. The text
# itself is copyright (C) ZTE, Inc.
##

include('compat.inc');

if (description)
{
  script_id(147310);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/03/10");

  script_cve_id(
    "CVE-2017-0393",
    "CVE-2019-9232",
    "CVE-2019-9433",
    "CVE-2020-0034"
  );
  script_bugtraq_id(95230);

  script_name(english:"NewStart CGSL CORE 5.04 / MAIN 5.04 : libvpx Multiple Vulnerabilities (NS-SA-2021-0015)");

  script_set_attribute(attribute:"synopsis", value:
"The remote machine is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote NewStart CGSL host, running version CORE 5.04 / MAIN 5.04, has libvpx packages installed that are affected by
multiple vulnerabilities:

  - A denial of service vulnerability in libvpx in Mediaserver could enable a remote attacker to use a
    specially crafted file to cause a device hang or reboot. This issue is rated as High due to the
    possibility of remote denial of service. Product: Android. Versions: 4.4.4, 5.0.2, 5.1.1, 6.0, 6.0.1, 7.0,
    7.1. Android ID: A-30436808. (CVE-2017-0393)

  - In vp8_decode_frame of decodeframe.c, there is a possible out of bounds read due to improper input
    validation. This could lead to remote information disclosure if error correction were turned on, with no
    additional execution privileges needed. User interaction is not needed for exploitation.Product:
    AndroidVersions: Android-8.0 Android-8.1Android ID: A-62458770 (CVE-2020-0034)

  - In libvpx, there is a possible out of bounds read due to a missing bounds check. This could lead to remote
    information disclosure with no additional execution privileges needed. User interaction is not needed for
    exploitation. Product: AndroidVersions: Android-10Android ID: A-122675483 (CVE-2019-9232)

  - In libvpx, there is a possible information disclosure due to improper input validation. This could lead to
    remote information disclosure with no additional execution privileges needed. User interaction is needed
    for exploitation. Product: AndroidVersions: Android-10Android ID: A-80479354 (CVE-2019-9433)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/notice/NS-SA-2021-0015");
  script_set_attribute(attribute:"solution", value:
"Upgrade the vulnerable CGSL libvpx packages. Note that updated packages may not be available yet. Please contact ZTE for
more information.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-0034");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/01/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/03/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/03/10");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"NewStart CGSL Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/ZTE-CGSL/release", "Host/ZTE-CGSL/rpm-list", "Host/cpu");

  exit(0);
}

include('audit.inc');
include('global_settings.inc');
include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

release = get_kb_item('Host/ZTE-CGSL/release');
if (isnull(release) || release !~ "^CGSL (MAIN|CORE)") audit(AUDIT_OS_NOT, 'NewStart Carrier Grade Server Linux');

if (release !~ "CGSL CORE 5.04" &&
    release !~ "CGSL MAIN 5.04")
  audit(AUDIT_OS_NOT, 'NewStart CGSL CORE 5.04 / NewStart CGSL MAIN 5.04');

if (!get_kb_item('Host/ZTE-CGSL/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'NewStart Carrier Grade Server Linux', cpu);

flag = 0;

pkgs = {
  'CGSL CORE 5.04': [
    'libvpx-1.3.0-8.el7',
    'libvpx-debuginfo-1.3.0-8.el7',
    'libvpx-devel-1.3.0-8.el7',
    'libvpx-utils-1.3.0-8.el7'
  ],
  'CGSL MAIN 5.04': [
    'libvpx-1.3.0-8.el7',
    'libvpx-debuginfo-1.3.0-8.el7',
    'libvpx-devel-1.3.0-8.el7',
    'libvpx-utils-1.3.0-8.el7'
  ]
};
pkg_list = pkgs[release];

foreach (pkg in pkg_list)
  if (rpm_check(release:'ZTE ' + release, reference:pkg)) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'libvpx');
}
