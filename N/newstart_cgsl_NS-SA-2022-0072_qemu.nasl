##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from ZTE advisory NS-SA-2022-0072. The text
# itself is copyright (C) ZTE, Inc.
##

include('compat.inc');

if (description)
{
  script_id(160817);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/09");

  script_cve_id("CVE-2019-15890");

  script_name(english:"NewStart CGSL MAIN 6.02 : qemu Vulnerability (NS-SA-2022-0072)");

  script_set_attribute(attribute:"synopsis", value:
"The remote NewStart CGSL host is affected by a vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote NewStart CGSL host, running version MAIN 6.02, has qemu packages installed that are affected by a
vulnerability:

  - libslirp 4.0.0, as used in QEMU 4.1.0, has a use-after-free in ip_reass in ip_input.c. (CVE-2019-15890)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/notice/NS-SA-2022-0072");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2019-15890");
  script_set_attribute(attribute:"solution", value:
"Upgrade the vulnerable CGSL qemu packages. Note that updated packages may not be available yet. Please contact ZTE for
more information.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-15890");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/09/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/05/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/05/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:qemu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:qemu-block-curl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:qemu-block-dmg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:qemu-block-gluster");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:qemu-block-iscsi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:qemu-block-rbd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:qemu-block-ssh");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:qemu-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:qemu-common-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:qemu-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:qemu-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:qemu-guest-agent");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:qemu-guest-agent-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:qemu-img");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:qemu-img-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:qemu-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:qemu-tools");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:zte:cgsl_main:6");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"NewStart CGSL Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/ZTE-CGSL/release", "Host/ZTE-CGSL/rpm-list", "Host/cpu");

  exit(0);
}

include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

var release = get_kb_item('Host/ZTE-CGSL/release');
if (isnull(release) || release !~ "^CGSL (MAIN|CORE)") audit(AUDIT_OS_NOT, 'NewStart Carrier Grade Server Linux');

if (release !~ "CGSL MAIN 6.02")
  audit(AUDIT_OS_NOT, 'NewStart CGSL MAIN 6.02');

if (!get_kb_item('Host/ZTE-CGSL/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'NewStart Carrier Grade Server Linux', cpu);

var flag = 0;

var pkgs = {
  'CGSL MAIN 6.02': [
    'qemu-4.1.0-2.el8.cgslv6_2.209.3.gf3409af5b',
    'qemu-block-curl-4.1.0-2.el8.cgslv6_2.209.3.gf3409af5b',
    'qemu-block-dmg-4.1.0-2.el8.cgslv6_2.209.3.gf3409af5b',
    'qemu-block-gluster-4.1.0-2.el8.cgslv6_2.209.3.gf3409af5b',
    'qemu-block-iscsi-4.1.0-2.el8.cgslv6_2.209.3.gf3409af5b',
    'qemu-block-rbd-4.1.0-2.el8.cgslv6_2.209.3.gf3409af5b',
    'qemu-block-ssh-4.1.0-2.el8.cgslv6_2.209.3.gf3409af5b',
    'qemu-common-4.1.0-2.el8.cgslv6_2.209.3.gf3409af5b',
    'qemu-common-debuginfo-4.1.0-2.el8.cgslv6_2.209.3.gf3409af5b',
    'qemu-debuginfo-4.1.0-2.el8.cgslv6_2.209.3.gf3409af5b',
    'qemu-debugsource-4.1.0-2.el8.cgslv6_2.209.3.gf3409af5b',
    'qemu-guest-agent-4.1.0-2.el8.cgslv6_2.209.3.gf3409af5b',
    'qemu-guest-agent-debuginfo-4.1.0-2.el8.cgslv6_2.209.3.gf3409af5b',
    'qemu-img-4.1.0-2.el8.cgslv6_2.209.3.gf3409af5b',
    'qemu-img-debuginfo-4.1.0-2.el8.cgslv6_2.209.3.gf3409af5b',
    'qemu-kvm-4.1.0-2.el8.cgslv6_2.209.3.gf3409af5b',
    'qemu-tools-4.1.0-2.el8.cgslv6_2.209.3.gf3409af5b'
  ]
};
var pkg_list = pkgs[release];

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
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'qemu');
}
