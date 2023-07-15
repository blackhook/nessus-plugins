##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from ZTE advisory NS-SA-2022-0064. The text
# itself is copyright (C) ZTE, Inc.
##

include('compat.inc');

if (description)
{
  script_id(160818);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/09");

  script_cve_id(
    "CVE-2019-25032",
    "CVE-2019-25034",
    "CVE-2019-25035",
    "CVE-2019-25036",
    "CVE-2019-25037",
    "CVE-2019-25038",
    "CVE-2019-25039",
    "CVE-2019-25040",
    "CVE-2019-25041",
    "CVE-2019-25042",
    "CVE-2020-28935"
  );

  script_name(english:"NewStart CGSL MAIN 6.02 : unbound Multiple Vulnerabilities (NS-SA-2022-0064)");

  script_set_attribute(attribute:"synopsis", value:
"The remote NewStart CGSL host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote NewStart CGSL host, running version MAIN 6.02, has unbound packages installed that are affected by multiple
vulnerabilities:

  - ** DISPUTED ** Unbound before 1.9.5 allows an integer overflow in the regional allocator via
    regional_alloc. NOTE: The vendor disputes that this is a vulnerability. Although the code may be
    vulnerable, a running Unbound installation cannot be remotely or locally exploited. (CVE-2019-25032)

  - ** DISPUTED ** Unbound before 1.9.5 allows an integer overflow in sldns_str2wire_dname_buf_origin, leading
    to an out-of-bounds write. NOTE: The vendor disputes that this is a vulnerability. Although the code may
    be vulnerable, a running Unbound installation cannot be remotely or locally exploited. (CVE-2019-25034)

  - ** DISPUTED ** Unbound before 1.9.5 allows an out-of-bounds write in sldns_bget_token_par. NOTE: The
    vendor disputes that this is a vulnerability. Although the code may be vulnerable, a running Unbound
    installation cannot be remotely or locally exploited. (CVE-2019-25035)

  - ** DISPUTED ** Unbound before 1.9.5 allows an assertion failure and denial of service in synth_cname.
    NOTE: The vendor disputes that this is a vulnerability. Although the code may be vulnerable, a running
    Unbound installation cannot be remotely or locally exploited. (CVE-2019-25036)

  - ** DISPUTED ** Unbound before 1.9.5 allows an assertion failure and denial of service in dname_pkt_copy
    via an invalid packet. NOTE: The vendor disputes that this is a vulnerability. Although the code may be
    vulnerable, a running Unbound installation cannot be remotely or locally exploited. (CVE-2019-25037)

  - ** DISPUTED ** Unbound before 1.9.5 allows an integer overflow in a size calculation in
    dnscrypt/dnscrypt.c. NOTE: The vendor disputes that this is a vulnerability. Although the code may be
    vulnerable, a running Unbound installation cannot be remotely or locally exploited. (CVE-2019-25038)

  - ** DISPUTED ** Unbound before 1.9.5 allows an integer overflow in a size calculation in respip/respip.c.
    NOTE: The vendor disputes that this is a vulnerability. Although the code may be vulnerable, a running
    Unbound installation cannot be remotely or locally exploited. (CVE-2019-25039)

  - ** DISPUTED ** Unbound before 1.9.5 allows an infinite loop via a compressed name in dname_pkt_copy. NOTE:
    The vendor disputes that this is a vulnerability. Although the code may be vulnerable, a running Unbound
    installation cannot be remotely or locally exploited. (CVE-2019-25040)

  - ** DISPUTED ** Unbound before 1.9.5 allows an assertion failure via a compressed name in dname_pkt_copy.
    NOTE: The vendor disputes that this is a vulnerability. Although the code may be vulnerable, a running
    Unbound installation cannot be remotely or locally exploited. (CVE-2019-25041)

  - ** DISPUTED ** Unbound before 1.9.5 allows an out-of-bounds write via a compressed name in rdata_copy.
    NOTE: The vendor disputes that this is a vulnerability. Although the code may be vulnerable, a running
    Unbound installation cannot be remotely or locally exploited. (CVE-2019-25042)

  - NLnet Labs Unbound, up to and including version 1.12.0, and NLnet Labs NSD, up to and including version
    4.3.3, contain a local vulnerability that would allow for a local symlink attack. When writing the PID
    file, Unbound and NSD create the file if it is not there, or open an existing file for writing. In case
    the file was already present, they would follow symlinks if the file happened to be a symlink instead of a
    regular file. An additional chown of the file would then take place after it was written, making the user
    Unbound/NSD is supposed to run as the new owner of the file. If an attacker has local access to the user
    Unbound/NSD runs as, she could create a symlink in place of the PID file pointing to a file that she would
    like to erase. If then Unbound/NSD is killed and the PID file is not cleared, upon restarting with root
    privileges, Unbound/NSD will rewrite any file pointed at by the symlink. This is a local vulnerability
    that could create a Denial of Service of the system Unbound/NSD is running on. It requires an attacker
    having access to the limited permission user Unbound/NSD runs as and point through the symlink to a
    critical file on the system. (CVE-2020-28935)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/notice/NS-SA-2022-0064");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2019-25032");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2019-25034");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2019-25035");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2019-25036");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2019-25037");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2019-25038");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2019-25039");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2019-25040");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2019-25041");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2019-25042");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2020-28935");
  script_set_attribute(attribute:"solution", value:
"Upgrade the vulnerable CGSL unbound packages. Note that updated packages may not be available yet. Please contact ZTE
for more information.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-25042");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/12/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/05/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/05/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:python3-unbound");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:python3-unbound-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:unbound");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:unbound-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:unbound-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:unbound-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:unbound-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:unbound-libs-debuginfo");
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
    'python3-unbound-1.7.3-15.el8',
    'python3-unbound-debuginfo-1.7.3-15.el8',
    'unbound-1.7.3-15.el8',
    'unbound-debuginfo-1.7.3-15.el8',
    'unbound-debugsource-1.7.3-15.el8',
    'unbound-devel-1.7.3-15.el8',
    'unbound-libs-1.7.3-15.el8',
    'unbound-libs-debuginfo-1.7.3-15.el8'
  ]
};
var pkg_list = pkgs[release];

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
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'unbound');
}
