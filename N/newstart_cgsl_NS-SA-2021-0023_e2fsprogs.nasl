##
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from ZTE advisory NS-SA-2021-0023. The text
# itself is copyright (C) ZTE, Inc.
##

include('compat.inc');

if (description)
{
  script_id(147290);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/03/10");

  script_cve_id("CVE-2019-5094", "CVE-2019-5188");

  script_name(english:"NewStart CGSL CORE 5.04 / MAIN 5.04 : e2fsprogs Multiple Vulnerabilities (NS-SA-2021-0023)");

  script_set_attribute(attribute:"synopsis", value:
"The remote machine is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote NewStart CGSL host, running version CORE 5.04 / MAIN 5.04, has e2fsprogs packages installed that are affected
by multiple vulnerabilities:

  - A code execution vulnerability exists in the directory rehashing functionality of E2fsprogs e2fsck 1.45.4.
    A specially crafted ext4 directory can cause an out-of-bounds write on the stack, resulting in code
    execution. An attacker can corrupt a partition to trigger this vulnerability. (CVE-2019-5188)

  - An exploitable code execution vulnerability exists in the quota file functionality of E2fsprogs 1.45.3. A
    specially crafted ext4 partition can cause an out-of-bounds write on the heap, resulting in code
    execution. An attacker can corrupt a partition to trigger this vulnerability. (CVE-2019-5094)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/notice/NS-SA-2021-0023");
  script_set_attribute(attribute:"solution", value:
"Upgrade the vulnerable CGSL e2fsprogs packages. Note that updated packages may not be available yet. Please contact ZTE
for more information.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-5188");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/09/24");
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
    'e2fsprogs-1.42.9-19.el7.cgslv5.0.2.g582fc58',
    'e2fsprogs-debuginfo-1.42.9-19.el7.cgslv5.0.2.g582fc58',
    'e2fsprogs-devel-1.42.9-19.el7.cgslv5.0.2.g582fc58',
    'e2fsprogs-libs-1.42.9-19.el7.cgslv5.0.2.g582fc58',
    'e2fsprogs-static-1.42.9-19.el7.cgslv5.0.2.g582fc58',
    'libcom_err-1.42.9-19.el7.cgslv5.0.2.g582fc58',
    'libcom_err-devel-1.42.9-19.el7.cgslv5.0.2.g582fc58',
    'libss-1.42.9-19.el7.cgslv5.0.2.g582fc58',
    'libss-devel-1.42.9-19.el7.cgslv5.0.2.g582fc58'
  ],
  'CGSL MAIN 5.04': [
    'e2fsprogs-1.42.9-19.el7.cgslv5.0.2.g582fc58',
    'e2fsprogs-debuginfo-1.42.9-19.el7.cgslv5.0.2.g582fc58',
    'e2fsprogs-devel-1.42.9-19.el7.cgslv5.0.2.g582fc58',
    'e2fsprogs-libs-1.42.9-19.el7.cgslv5.0.2.g582fc58',
    'e2fsprogs-static-1.42.9-19.el7.cgslv5.0.2.g582fc58',
    'libcom_err-1.42.9-19.el7.cgslv5.0.2.g582fc58',
    'libcom_err-devel-1.42.9-19.el7.cgslv5.0.2.g582fc58',
    'libss-1.42.9-19.el7.cgslv5.0.2.g582fc58',
    'libss-devel-1.42.9-19.el7.cgslv5.0.2.g582fc58'
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'e2fsprogs');
}
