##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from ZTE advisory NS-SA-2022-0067. The text
# itself is copyright (C) ZTE, Inc.
##

include('compat.inc');

if (description)
{
  script_id(160844);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/10");

  script_cve_id("CVE-2021-35942");

  script_name(english:"NewStart CGSL MAIN 6.02 : glibc Vulnerability (NS-SA-2022-0067)");

  script_set_attribute(attribute:"synopsis", value:
"The remote NewStart CGSL host is affected by a vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote NewStart CGSL host, running version MAIN 6.02, has glibc packages installed that are affected by a
vulnerability:

  - The wordexp function in the GNU C Library (aka glibc) through 2.33 may crash or read arbitrary memory in
    parse_param (in posix/wordexp.c) when called with an untrusted, crafted pattern, potentially resulting in
    a denial of service or disclosure of information. This occurs because atoi was used but strtoul should
    have been used to ensure correct calculations. (CVE-2021-35942)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/notice/NS-SA-2022-0067");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2021-35942");
  script_set_attribute(attribute:"solution", value:
"Upgrade the vulnerable CGSL glibc packages. Note that updated packages may not be available yet. Please contact ZTE for
more information.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-35942");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/07/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/05/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/05/10");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:compat-libpthread-nonshared");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:glibc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:glibc-all-langpacks");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:glibc-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:glibc-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:glibc-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:glibc-langpack-en");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:glibc-langpack-zh");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:glibc-locale-source");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:glibc-minimal-langpack");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:glibc-static");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:libnsl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:nscd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:nss_db");
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
    'compat-libpthread-nonshared-2.28-127.el8.cgslv6_2.3.g008645c4',
    'glibc-2.28-127.el8.cgslv6_2.3.g008645c4',
    'glibc-all-langpacks-2.28-127.el8.cgslv6_2.3.g008645c4',
    'glibc-common-2.28-127.el8.cgslv6_2.3.g008645c4',
    'glibc-devel-2.28-127.el8.cgslv6_2.3.g008645c4',
    'glibc-headers-2.28-127.el8.cgslv6_2.3.g008645c4',
    'glibc-langpack-en-2.28-127.el8.cgslv6_2.3.g008645c4',
    'glibc-langpack-zh-2.28-127.el8.cgslv6_2.3.g008645c4',
    'glibc-locale-source-2.28-127.el8.cgslv6_2.3.g008645c4',
    'glibc-minimal-langpack-2.28-127.el8.cgslv6_2.3.g008645c4',
    'glibc-static-2.28-127.el8.cgslv6_2.3.g008645c4',
    'libnsl-2.28-127.el8.cgslv6_2.3.g008645c4',
    'nscd-2.28-127.el8.cgslv6_2.3.g008645c4',
    'nss_db-2.28-127.el8.cgslv6_2.3.g008645c4'
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'glibc');
}
