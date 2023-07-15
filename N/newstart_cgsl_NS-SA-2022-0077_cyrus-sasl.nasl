#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from ZTE advisory NS-SA-2022-0077. The text
# itself is copyright (C) ZTE, Inc.
##

include('compat.inc');

if (description)
{
  script_id(167505);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/11/15");

  script_cve_id("CVE-2022-24407");

  script_name(english:"NewStart CGSL CORE 5.04 / MAIN 5.04 : cyrus-sasl Vulnerability (NS-SA-2022-0077)");

  script_set_attribute(attribute:"synopsis", value:
"The remote NewStart CGSL host is affected by a vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote NewStart CGSL host, running version CORE 5.04 / MAIN 5.04, has cyrus-sasl packages installed that are
affected by a vulnerability:

  - In Cyrus SASL 2.1.17 through 2.1.27 before 2.1.28, plugins/sql.c does not escape the password for a SQL
    INSERT or UPDATE statement. (CVE-2022-24407)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/notice/NS-SA-2022-0077");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2022-24407");
  script_set_attribute(attribute:"solution", value:
"Upgrade the vulnerable CGSL cyrus-sasl packages. Note that updated packages may not be available yet. Please contact ZTE
for more information.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-24407");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/02/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/11/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/11/15");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:cyrus-sasl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:cyrus-sasl-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:cyrus-sasl-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:cyrus-sasl-gs2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:cyrus-sasl-gssapi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:cyrus-sasl-ldap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:cyrus-sasl-lib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:cyrus-sasl-md5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:cyrus-sasl-ntlm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:cyrus-sasl-plain");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:cyrus-sasl-scram");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:cyrus-sasl-sql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:cyrus-sasl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:cyrus-sasl-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:cyrus-sasl-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:cyrus-sasl-gs2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:cyrus-sasl-gssapi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:cyrus-sasl-ldap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:cyrus-sasl-lib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:cyrus-sasl-md5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:cyrus-sasl-ntlm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:cyrus-sasl-plain");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:cyrus-sasl-scram");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:cyrus-sasl-sql");
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

var os_release = get_kb_item('Host/ZTE-CGSL/release');
if (isnull(os_release) || os_release !~ "^CGSL (MAIN|CORE)") audit(AUDIT_OS_NOT, 'NewStart Carrier Grade Server Linux');

if (os_release !~ "CGSL CORE 5.04" &&
    os_release !~ "CGSL MAIN 5.04")
  audit(AUDIT_OS_NOT, 'NewStart CGSL CORE 5.04 / NewStart CGSL MAIN 5.04');

if (!get_kb_item('Host/ZTE-CGSL/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'NewStart Carrier Grade Server Linux', cpu);

var flag = 0;

var pkgs = {
  'CGSL CORE 5.04': [
    'cyrus-sasl-2.1.26-24.el7_9',
    'cyrus-sasl-debuginfo-2.1.26-24.el7_9',
    'cyrus-sasl-devel-2.1.26-24.el7_9',
    'cyrus-sasl-gs2-2.1.26-24.el7_9',
    'cyrus-sasl-gssapi-2.1.26-24.el7_9',
    'cyrus-sasl-ldap-2.1.26-24.el7_9',
    'cyrus-sasl-lib-2.1.26-24.el7_9',
    'cyrus-sasl-md5-2.1.26-24.el7_9',
    'cyrus-sasl-ntlm-2.1.26-24.el7_9',
    'cyrus-sasl-plain-2.1.26-24.el7_9',
    'cyrus-sasl-scram-2.1.26-24.el7_9',
    'cyrus-sasl-sql-2.1.26-24.el7_9'
  ],
  'CGSL MAIN 5.04': [
    'cyrus-sasl-2.1.26-24.el7_9',
    'cyrus-sasl-debuginfo-2.1.26-24.el7_9',
    'cyrus-sasl-devel-2.1.26-24.el7_9',
    'cyrus-sasl-gs2-2.1.26-24.el7_9',
    'cyrus-sasl-gssapi-2.1.26-24.el7_9',
    'cyrus-sasl-ldap-2.1.26-24.el7_9',
    'cyrus-sasl-lib-2.1.26-24.el7_9',
    'cyrus-sasl-md5-2.1.26-24.el7_9',
    'cyrus-sasl-ntlm-2.1.26-24.el7_9',
    'cyrus-sasl-plain-2.1.26-24.el7_9',
    'cyrus-sasl-scram-2.1.26-24.el7_9',
    'cyrus-sasl-sql-2.1.26-24.el7_9'
  ]
};
var pkg_list = pkgs[os_release];

foreach (pkg in pkg_list)
  if (rpm_check(release:'ZTE ' + os_release, reference:pkg)) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'cyrus-sasl');
}
