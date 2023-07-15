##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from ZTE advisory NS-SA-2022-0037. The text
# itself is copyright (C) ZTE, Inc.
##

include('compat.inc');

if (description)
{
  script_id(160771);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/09");

  script_cve_id("CVE-2011-1098", "CVE-2011-1154", "CVE-2011-1155");

  script_name(english:"NewStart CGSL CORE 5.05 / MAIN 5.05 : logrotate Multiple Vulnerabilities (NS-SA-2022-0037)");

  script_set_attribute(attribute:"synopsis", value:
"The remote NewStart CGSL host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote NewStart CGSL host, running version CORE 5.05 / MAIN 5.05, has logrotate packages installed that are affected
by multiple vulnerabilities:

  - Race condition in the createOutputFile function in logrotate.c in logrotate 3.7.9 and earlier allows local
    users to read log data by opening a file before the intended permissions are in place. (CVE-2011-1098)

  - The shred_file function in logrotate.c in logrotate 3.7.9 and earlier might allow context-dependent
    attackers to execute arbitrary commands via shell metacharacters in a log filename, as demonstrated by a
    filename that is automatically constructed on the basis of a hostname or virtual machine name.
    (CVE-2011-1154)

  - The writeState function in logrotate.c in logrotate 3.7.9 and earlier might allow context-dependent
    attackers to cause a denial of service (rotation outage) via a (1) \n (newline) or (2) \ (backslash)
    character in a log filename, as demonstrated by a filename that is automatically constructed on the basis
    of a hostname or virtual machine name. (CVE-2011-1155)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/notice/NS-SA-2022-0037");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2011-1098");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2011-1154");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2011-1155");
  script_set_attribute(attribute:"solution", value:
"Upgrade the vulnerable CGSL logrotate packages. Note that updated packages may not be available yet. Please contact ZTE
for more information.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2011-1154");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2011-1098");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/03/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/05/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/05/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:logrotate");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:logrotate-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:logrotate");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:logrotate-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:zte:cgsl_core:5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:zte:cgsl_main:5");
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

if (release !~ "CGSL CORE 5.05" &&
    release !~ "CGSL MAIN 5.05")
  audit(AUDIT_OS_NOT, 'NewStart CGSL CORE 5.05 / NewStart CGSL MAIN 5.05');

if (!get_kb_item('Host/ZTE-CGSL/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'NewStart Carrier Grade Server Linux', cpu);

var flag = 0;

var pkgs = {
  'CGSL CORE 5.05': [
    'logrotate-3.8.6-17.el7.cgslv5_5.0.1.gcda2743',
    'logrotate-debuginfo-3.8.6-17.el7.cgslv5_5.0.1.gcda2743'
  ],
  'CGSL MAIN 5.05': [
    'logrotate-3.8.6-17.el7.cgslv5_5.0.1.gcda2743',
    'logrotate-debuginfo-3.8.6-17.el7.cgslv5_5.0.1.gcda2743'
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'logrotate');
}
