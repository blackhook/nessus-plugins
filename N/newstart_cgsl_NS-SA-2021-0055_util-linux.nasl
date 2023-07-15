##
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from ZTE advisory NS-SA-2021-0055. The text
# itself is copyright (C) ZTE, Inc.
##

include('compat.inc');

if (description)
{
  script_id(147355);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/03/11");

  script_cve_id("CVE-2014-9114");
  script_bugtraq_id(71327);

  script_name(english:"NewStart CGSL MAIN 6.02 : util-linux Vulnerability (NS-SA-2021-0055)");

  script_set_attribute(attribute:"synopsis", value:
"The remote machine is affected by a vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote NewStart CGSL host, running version MAIN 6.02, has util-linux packages installed that are affected by a
vulnerability:

  - Blkid in util-linux before 2.26rc-1 allows local users to execute arbitrary code. (CVE-2014-9114)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/notice/NS-SA-2021-0055");
  script_set_attribute(attribute:"solution", value:
"Upgrade the vulnerable CGSL util-linux packages. Note that updated packages may not be available yet. Please contact ZTE
for more information.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2014-9114");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/11/27");
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

if (release !~ "CGSL MAIN 6.02")
  audit(AUDIT_OS_NOT, 'NewStart CGSL MAIN 6.02');

if (!get_kb_item('Host/ZTE-CGSL/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'NewStart Carrier Grade Server Linux', cpu);

flag = 0;

pkgs = {
  'CGSL MAIN 6.02': [
    'libblkid-2.32.1-22.el8.cgslv6_2.0.1.ge664644',
    'libblkid-debuginfo-2.32.1-22.el8.cgslv6_2.0.1.ge664644',
    'libblkid-devel-2.32.1-22.el8.cgslv6_2.0.1.ge664644',
    'libfdisk-2.32.1-22.el8.cgslv6_2.0.1.ge664644',
    'libfdisk-debuginfo-2.32.1-22.el8.cgslv6_2.0.1.ge664644',
    'libfdisk-devel-2.32.1-22.el8.cgslv6_2.0.1.ge664644',
    'libmount-2.32.1-22.el8.cgslv6_2.0.1.ge664644',
    'libmount-debuginfo-2.32.1-22.el8.cgslv6_2.0.1.ge664644',
    'libmount-devel-2.32.1-22.el8.cgslv6_2.0.1.ge664644',
    'libsmartcols-2.32.1-22.el8.cgslv6_2.0.1.ge664644',
    'libsmartcols-debuginfo-2.32.1-22.el8.cgslv6_2.0.1.ge664644',
    'libsmartcols-devel-2.32.1-22.el8.cgslv6_2.0.1.ge664644',
    'libuuid-2.32.1-22.el8.cgslv6_2.0.1.ge664644',
    'libuuid-debuginfo-2.32.1-22.el8.cgslv6_2.0.1.ge664644',
    'libuuid-devel-2.32.1-22.el8.cgslv6_2.0.1.ge664644',
    'python3-libmount-2.32.1-22.el8.cgslv6_2.0.1.ge664644',
    'python3-libmount-debuginfo-2.32.1-22.el8.cgslv6_2.0.1.ge664644',
    'util-linux-2.32.1-22.el8.cgslv6_2.0.1.ge664644',
    'util-linux-debuginfo-2.32.1-22.el8.cgslv6_2.0.1.ge664644',
    'util-linux-debugsource-2.32.1-22.el8.cgslv6_2.0.1.ge664644',
    'util-linux-user-2.32.1-22.el8.cgslv6_2.0.1.ge664644',
    'util-linux-user-debuginfo-2.32.1-22.el8.cgslv6_2.0.1.ge664644',
    'uuidd-2.32.1-22.el8.cgslv6_2.0.1.ge664644',
    'uuidd-debuginfo-2.32.1-22.el8.cgslv6_2.0.1.ge664644'
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'util-linux');
}
