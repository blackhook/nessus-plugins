#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from ZTE advisory NS-SA-2021-0151. The text
# itself is copyright (C) ZTE, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(154528);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/10/28");

  script_cve_id("CVE-2019-10143", "CVE-2019-13456", "CVE-2019-17185");

  script_name(english:"NewStart CGSL CORE 5.05 / MAIN 5.05 : freeradius Multiple Vulnerabilities (NS-SA-2021-0151)");

  script_set_attribute(attribute:"synopsis", value:
"The remote NewStart CGSL host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote NewStart CGSL host, running version CORE 5.05 / MAIN 5.05, has freeradius packages installed that are
affected by multiple vulnerabilities:

  - ** DISPUTED ** It was discovered freeradius up to and including version 3.0.19 does not correctly
    configure logrotate, allowing a local attacker who already has control of the radiusd user to escalate his
    privileges to root, by tricking logrotate into writing a radiusd-writable file to a directory normally
    inaccessible by the radiusd user. NOTE: the upstream software maintainer has stated there is simply no
    way for anyone to gain privileges through this alleged issue. (CVE-2019-10143)

  - In FreeRADIUS 3.0 through 3.0.19, on average 1 in every 2048 EAP-pwd handshakes fails because the password
    element cannot be found within 10 iterations of the hunting and pecking loop. This leaks information that
    an attacker can use to recover the password of any user. This information leakage is similar to the
    Dragonblood attack and CVE-2019-9494. (CVE-2019-13456)

  - In FreeRADIUS 3.0.x before 3.0.20, the EAP-pwd module used a global OpenSSL BN_CTX instance to handle all
    handshakes. This mean multiple threads use the same BN_CTX instance concurrently, resulting in crashes
    when concurrent EAP-pwd handshakes are initiated. This can be abused by an adversary as a Denial-of-
    Service (DoS) attack. (CVE-2019-17185)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/notice/NS-SA-2021-0151");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2019-10143");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2019-13456");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2019-17185");
  script_set_attribute(attribute:"solution", value:
"Upgrade the vulnerable CGSL freeradius packages. Note that updated packages may not be available yet. Please contact ZTE
for more information.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-10143");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/05/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/09/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/10/27");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:freeradius");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:freeradius-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:freeradius-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:freeradius-krb5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:freeradius-ldap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:freeradius-mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:freeradius-perl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:freeradius-postgresql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:freeradius-python");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:freeradius-sqlite");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:freeradius-unixODBC");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:freeradius-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:freeradius");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:freeradius-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:freeradius-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:freeradius-krb5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:freeradius-ldap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:freeradius-mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:freeradius-perl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:freeradius-postgresql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:freeradius-python");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:freeradius-sqlite");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:freeradius-unixODBC");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:freeradius-utils");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:zte:cgsl_core:5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:zte:cgsl_main:5");
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
    'freeradius-3.0.13-15.el7',
    'freeradius-devel-3.0.13-15.el7',
    'freeradius-doc-3.0.13-15.el7',
    'freeradius-krb5-3.0.13-15.el7',
    'freeradius-ldap-3.0.13-15.el7',
    'freeradius-mysql-3.0.13-15.el7',
    'freeradius-perl-3.0.13-15.el7',
    'freeradius-postgresql-3.0.13-15.el7',
    'freeradius-python-3.0.13-15.el7',
    'freeradius-sqlite-3.0.13-15.el7',
    'freeradius-unixODBC-3.0.13-15.el7',
    'freeradius-utils-3.0.13-15.el7'
  ],
  'CGSL MAIN 5.05': [
    'freeradius-3.0.13-15.el7',
    'freeradius-devel-3.0.13-15.el7',
    'freeradius-doc-3.0.13-15.el7',
    'freeradius-krb5-3.0.13-15.el7',
    'freeradius-ldap-3.0.13-15.el7',
    'freeradius-mysql-3.0.13-15.el7',
    'freeradius-perl-3.0.13-15.el7',
    'freeradius-postgresql-3.0.13-15.el7',
    'freeradius-python-3.0.13-15.el7',
    'freeradius-sqlite-3.0.13-15.el7',
    'freeradius-unixODBC-3.0.13-15.el7',
    'freeradius-utils-3.0.13-15.el7'
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'freeradius');
}
