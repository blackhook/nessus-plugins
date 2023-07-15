##
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from ZTE advisory NS-SA-2021-0012. The text
# itself is copyright (C) ZTE, Inc.
##

include('compat.inc');

if (description)
{
  script_id(147338);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/03/11");

  script_cve_id("CVE-2020-25212", "CVE-2020-25284");

  script_name(english:"NewStart CGSL CORE 5.04 / MAIN 5.04 : kernel Multiple Vulnerabilities (NS-SA-2021-0012)");

  script_set_attribute(attribute:"synopsis", value:
"The remote machine is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote NewStart CGSL host, running version CORE 5.04 / MAIN 5.04, has kernel packages installed that are affected by
multiple vulnerabilities:

  - A TOCTOU mismatch in the NFS client code in the Linux kernel before 5.8.3 could be used by local attackers
    to corrupt memory or possibly have unspecified other impact because a size check is in fs/nfs/nfs4proc.c
    instead of fs/nfs/nfs4xdr.c, aka CID-b4487b935452. (CVE-2020-25212)

  - The rbd block device driver in drivers/block/rbd.c in the Linux kernel through 5.8.9 used incomplete
    permission checking for access to rbd devices, which could be leveraged by local attackers to map or unmap
    rbd block devices, aka CID-f44d04e696fe. (CVE-2020-25284)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/notice/NS-SA-2021-0012");
  script_set_attribute(attribute:"solution", value:
"Upgrade the vulnerable CGSL kernel packages. Note that updated packages may not be available yet. Please contact ZTE for
more information.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-25212");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/09/09");
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
    'kernel-3.10.0-693.21.1.el7.cgslv5_4.52.871.g8c342d3.lite',
    'kernel-abi-whitelists-3.10.0-693.21.1.el7.cgslv5_4.52.871.g8c342d3.lite',
    'kernel-core-3.10.0-693.21.1.el7.cgslv5_4.52.871.g8c342d3.lite',
    'kernel-debug-core-3.10.0-693.21.1.el7.cgslv5_4.52.871.g8c342d3.lite',
    'kernel-debug-debuginfo-3.10.0-693.21.1.el7.cgslv5_4.52.871.g8c342d3.lite',
    'kernel-debug-devel-3.10.0-693.21.1.el7.cgslv5_4.52.871.g8c342d3.lite',
    'kernel-debug-modules-3.10.0-693.21.1.el7.cgslv5_4.52.871.g8c342d3.lite',
    'kernel-debuginfo-3.10.0-693.21.1.el7.cgslv5_4.52.871.g8c342d3.lite',
    'kernel-debuginfo-common-x86_64-3.10.0-693.21.1.el7.cgslv5_4.52.871.g8c342d3.lite',
    'kernel-devel-3.10.0-693.21.1.el7.cgslv5_4.52.871.g8c342d3.lite',
    'kernel-headers-3.10.0-693.21.1.el7.cgslv5_4.52.871.g8c342d3.lite',
    'kernel-modules-3.10.0-693.21.1.el7.cgslv5_4.52.871.g8c342d3.lite',
    'kernel-sign-keys-3.10.0-693.21.1.el7.cgslv5_4.52.871.g8c342d3.lite',
    'kernel-tools-3.10.0-693.21.1.el7.cgslv5_4.52.871.g8c342d3.lite',
    'kernel-tools-debuginfo-3.10.0-693.21.1.el7.cgslv5_4.52.871.g8c342d3.lite',
    'kernel-tools-libs-3.10.0-693.21.1.el7.cgslv5_4.52.871.g8c342d3.lite',
    'kernel-tools-libs-devel-3.10.0-693.21.1.el7.cgslv5_4.52.871.g8c342d3.lite',
    'perf-3.10.0-693.21.1.el7.cgslv5_4.52.871.g8c342d3.lite',
    'perf-debuginfo-3.10.0-693.21.1.el7.cgslv5_4.52.871.g8c342d3.lite',
    'python-perf-3.10.0-693.21.1.el7.cgslv5_4.52.871.g8c342d3.lite',
    'python-perf-debuginfo-3.10.0-693.21.1.el7.cgslv5_4.52.871.g8c342d3.lite'
  ],
  'CGSL MAIN 5.04': [
    'kernel-3.10.0-693.21.1.el7.cgslv5_4.51.912.gf6a1413',
    'kernel-debug-3.10.0-693.21.1.el7.cgslv5_4.51.912.gf6a1413',
    'kernel-debug-devel-3.10.0-693.21.1.el7.cgslv5_4.51.912.gf6a1413',
    'kernel-devel-3.10.0-693.21.1.el7.cgslv5_4.51.912.gf6a1413',
    'kernel-headers-3.10.0-693.21.1.el7.cgslv5_4.51.912.gf6a1413',
    'kernel-sign-keys-3.10.0-693.21.1.el7.cgslv5_4.51.912.gf6a1413',
    'kernel-tools-3.10.0-693.21.1.el7.cgslv5_4.51.912.gf6a1413',
    'kernel-tools-libs-3.10.0-693.21.1.el7.cgslv5_4.51.912.gf6a1413',
    'kernel-tools-libs-devel-3.10.0-693.21.1.el7.cgslv5_4.51.912.gf6a1413',
    'perf-3.10.0-693.21.1.el7.cgslv5_4.51.912.gf6a1413',
    'python-perf-3.10.0-693.21.1.el7.cgslv5_4.51.912.gf6a1413'
  ]
};
pkg_list = pkgs[release];

foreach (pkg in pkg_list)
  if (rpm_check(release:'ZTE ' + release, reference:pkg)) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'kernel');
}
