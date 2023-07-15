#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from ZTE advisory NS-SA-2021-0116. The text
# itself is copyright (C) ZTE, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(154534);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/10/27");

  script_cve_id("CVE-2021-32027");
  script_xref(name:"IAVB", value:"2021-B-0036-S");

  script_name(english:"NewStart CGSL CORE 5.04 / MAIN 5.04 : postgresql Vulnerability (NS-SA-2021-0116)");

  script_set_attribute(attribute:"synopsis", value:
"The remote NewStart CGSL host is affected by a vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote NewStart CGSL host, running version CORE 5.04 / MAIN 5.04, has postgresql packages installed that are
affected by a vulnerability:

  - A flaw was found in postgresql in versions before 13.3, before 12.7, before 11.12, before 10.17 and before
    9.6.22. While modifying certain SQL array values, missing bounds checks let authenticated database users
    write arbitrary bytes to a wide area of server memory. The highest threat from this vulnerability is to
    data confidentiality and integrity as well as system availability. (CVE-2021-32027)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/notice/NS-SA-2021-0116");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2021-32027");
  script_set_attribute(attribute:"solution", value:
"Upgrade the vulnerable CGSL postgresql packages. Note that updated packages may not be available yet. Please contact ZTE
for more information.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-32027");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/05/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/09/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/10/27");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:postgresql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:postgresql-contrib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:postgresql-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:postgresql-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:postgresql-docs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:postgresql-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:postgresql-plperl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:postgresql-plpython");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:postgresql-pltcl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:postgresql-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:postgresql-static");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:postgresql-test");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:postgresql-upgrade");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:postgresql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:postgresql-contrib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:postgresql-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:postgresql-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:postgresql-docs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:postgresql-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:postgresql-plperl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:postgresql-plpython");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:postgresql-pltcl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:postgresql-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:postgresql-static");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:postgresql-test");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:postgresql-upgrade");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:zte:cgsl_core:5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:zte:cgsl_main:5");
  script_set_attribute(attribute:"stig_severity", value:"I");
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

var release = get_kb_item('Host/ZTE-CGSL/release');
if (isnull(release) || release !~ "^CGSL (MAIN|CORE)") audit(AUDIT_OS_NOT, 'NewStart Carrier Grade Server Linux');

if (release !~ "CGSL CORE 5.04" &&
    release !~ "CGSL MAIN 5.04")
  audit(AUDIT_OS_NOT, 'NewStart CGSL CORE 5.04 / NewStart CGSL MAIN 5.04');

if (!get_kb_item('Host/ZTE-CGSL/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'NewStart Carrier Grade Server Linux', cpu);

var flag = 0;

var pkgs = {
  'CGSL CORE 5.04': [
    'postgresql-9.2.24-7.el7_9',
    'postgresql-contrib-9.2.24-7.el7_9',
    'postgresql-debuginfo-9.2.24-7.el7_9',
    'postgresql-devel-9.2.24-7.el7_9',
    'postgresql-docs-9.2.24-7.el7_9',
    'postgresql-libs-9.2.24-7.el7_9',
    'postgresql-plperl-9.2.24-7.el7_9',
    'postgresql-plpython-9.2.24-7.el7_9',
    'postgresql-pltcl-9.2.24-7.el7_9',
    'postgresql-server-9.2.24-7.el7_9',
    'postgresql-static-9.2.24-7.el7_9',
    'postgresql-test-9.2.24-7.el7_9',
    'postgresql-upgrade-9.2.24-7.el7_9'
  ],
  'CGSL MAIN 5.04': [
    'postgresql-9.2.24-7.el7_9',
    'postgresql-contrib-9.2.24-7.el7_9',
    'postgresql-debuginfo-9.2.24-7.el7_9',
    'postgresql-devel-9.2.24-7.el7_9',
    'postgresql-docs-9.2.24-7.el7_9',
    'postgresql-libs-9.2.24-7.el7_9',
    'postgresql-plperl-9.2.24-7.el7_9',
    'postgresql-plpython-9.2.24-7.el7_9',
    'postgresql-pltcl-9.2.24-7.el7_9',
    'postgresql-server-9.2.24-7.el7_9',
    'postgresql-static-9.2.24-7.el7_9',
    'postgresql-test-9.2.24-7.el7_9',
    'postgresql-upgrade-9.2.24-7.el7_9'
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'postgresql');
}
