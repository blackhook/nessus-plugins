#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# Rocky Linux Security Advisory RLSA-2022:8197.
##

include('compat.inc');

if (description)
{
  script_id(170714);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/21");

  script_cve_id("CVE-2021-21708", "CVE-2022-31625");
  script_xref(name:"RLSA", value:"2022:8197");

  script_name(english:"Rocky Linux 9 : php (RLSA-2022:8197)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Rocky Linux host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Rocky Linux 9 host has packages installed that are affected by a vulnerability as referenced in the
RLSA-2022:8197 advisory.

  - In PHP versions 7.4.x below 7.4.30, 8.0.x below 8.0.20, and 8.1.x below 8.1.7, when using Postgres
    database extension, supplying invalid parameters to the parametrized query may lead to PHP attempting to
    free memory using uninitialized data as pointers. This could lead to RCE vulnerability or denial of
    service. (CVE-2022-31625)

  - In PHP versions 7.4.x below 7.4.28, 8.0.x below 8.0.16, and 8.1.x below 8.1.3, when using filter functions
    with FILTER_VALIDATE_FLOAT filter and min/max limits, if the filter fails, there is a possibility to
    trigger use of allocated memory after free, which can result it crashes, and potentially in overwrite of
    other memory chunks and RCE. This issue affects: code that uses FILTER_VALIDATE_FLOAT with min/max limits.
    (CVE-2021-21708)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://errata.rockylinux.org/RLSA-2022:8197");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2055879");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2095447");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2095752");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2098521");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2104630");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-31625");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2021-21708");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/01/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/01/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/01/27");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:php");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:php-bcmath");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:php-bcmath-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:php-cli");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:php-cli-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:php-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:php-common-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:php-dba");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:php-dba-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:php-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:php-dbg-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:php-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:php-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:php-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:php-embedded");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:php-embedded-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:php-enchant");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:php-enchant-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:php-ffi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:php-ffi-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:php-fpm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:php-fpm-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:php-gd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:php-gd-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:php-gmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:php-gmp-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:php-intl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:php-intl-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:php-ldap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:php-ldap-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:php-mbstring");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:php-mbstring-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:php-mysqlnd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:php-mysqlnd-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:php-odbc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:php-odbc-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:php-opcache");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:php-opcache-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:php-pdo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:php-pdo-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:php-pgsql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:php-pgsql-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:php-process");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:php-process-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:php-snmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:php-snmp-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:php-soap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:php-soap-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:php-xml");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:php-xml-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:rocky:linux:9");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Rocky Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/RockyLinux/release", "Host/RockyLinux/rpm-list", "Host/cpu");

  exit(0);
}


include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item('Host/RockyLinux/release');
if (isnull(os_release) || 'Rocky Linux' >!< os_release) audit(AUDIT_OS_NOT, 'Rocky Linux');
var os_ver = pregmatch(pattern: "Rocky(?: Linux)? release ([0-9]+(\.[0-9]+)?)", string:os_release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'Rocky Linux');
os_ver = os_ver[1];
if (! preg(pattern:"^9([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, 'Rocky Linux 9.x', 'Rocky Linux ' + os_ver);

if (!get_kb_item('Host/RockyLinux/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Rocky Linux', cpu);

var pkgs = [
    {'reference':'php-8.0.20-3.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php-8.0.20-3.el9', 'cpu':'i686', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php-8.0.20-3.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php-bcmath-8.0.20-3.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php-bcmath-8.0.20-3.el9', 'cpu':'i686', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php-bcmath-8.0.20-3.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php-bcmath-debuginfo-8.0.20-3.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php-bcmath-debuginfo-8.0.20-3.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php-cli-8.0.20-3.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php-cli-8.0.20-3.el9', 'cpu':'i686', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php-cli-8.0.20-3.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php-cli-debuginfo-8.0.20-3.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php-cli-debuginfo-8.0.20-3.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php-common-8.0.20-3.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php-common-8.0.20-3.el9', 'cpu':'i686', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php-common-8.0.20-3.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php-common-debuginfo-8.0.20-3.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php-common-debuginfo-8.0.20-3.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php-dba-8.0.20-3.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php-dba-8.0.20-3.el9', 'cpu':'i686', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php-dba-8.0.20-3.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php-dba-debuginfo-8.0.20-3.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php-dba-debuginfo-8.0.20-3.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php-dbg-8.0.20-3.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php-dbg-8.0.20-3.el9', 'cpu':'i686', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php-dbg-8.0.20-3.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php-dbg-debuginfo-8.0.20-3.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php-dbg-debuginfo-8.0.20-3.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php-debuginfo-8.0.20-3.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php-debuginfo-8.0.20-3.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php-debugsource-8.0.20-3.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php-debugsource-8.0.20-3.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php-devel-8.0.20-3.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php-devel-8.0.20-3.el9', 'cpu':'i686', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php-devel-8.0.20-3.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php-embedded-8.0.20-3.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php-embedded-8.0.20-3.el9', 'cpu':'i686', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php-embedded-8.0.20-3.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php-embedded-debuginfo-8.0.20-3.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php-embedded-debuginfo-8.0.20-3.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php-enchant-8.0.20-3.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php-enchant-8.0.20-3.el9', 'cpu':'i686', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php-enchant-8.0.20-3.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php-enchant-debuginfo-8.0.20-3.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php-enchant-debuginfo-8.0.20-3.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php-ffi-8.0.20-3.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php-ffi-8.0.20-3.el9', 'cpu':'i686', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php-ffi-8.0.20-3.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php-ffi-debuginfo-8.0.20-3.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php-ffi-debuginfo-8.0.20-3.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php-fpm-8.0.20-3.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php-fpm-8.0.20-3.el9', 'cpu':'i686', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php-fpm-8.0.20-3.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php-fpm-debuginfo-8.0.20-3.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php-fpm-debuginfo-8.0.20-3.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php-gd-8.0.20-3.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php-gd-8.0.20-3.el9', 'cpu':'i686', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php-gd-8.0.20-3.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php-gd-debuginfo-8.0.20-3.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php-gd-debuginfo-8.0.20-3.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php-gmp-8.0.20-3.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php-gmp-8.0.20-3.el9', 'cpu':'i686', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php-gmp-8.0.20-3.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php-gmp-debuginfo-8.0.20-3.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php-gmp-debuginfo-8.0.20-3.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php-intl-8.0.20-3.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php-intl-8.0.20-3.el9', 'cpu':'i686', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php-intl-8.0.20-3.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php-intl-debuginfo-8.0.20-3.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php-intl-debuginfo-8.0.20-3.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php-ldap-8.0.20-3.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php-ldap-8.0.20-3.el9', 'cpu':'i686', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php-ldap-8.0.20-3.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php-ldap-debuginfo-8.0.20-3.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php-ldap-debuginfo-8.0.20-3.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php-mbstring-8.0.20-3.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php-mbstring-8.0.20-3.el9', 'cpu':'i686', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php-mbstring-8.0.20-3.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php-mbstring-debuginfo-8.0.20-3.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php-mbstring-debuginfo-8.0.20-3.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php-mysqlnd-8.0.20-3.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php-mysqlnd-8.0.20-3.el9', 'cpu':'i686', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php-mysqlnd-8.0.20-3.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php-mysqlnd-debuginfo-8.0.20-3.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php-mysqlnd-debuginfo-8.0.20-3.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php-odbc-8.0.20-3.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php-odbc-8.0.20-3.el9', 'cpu':'i686', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php-odbc-8.0.20-3.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php-odbc-debuginfo-8.0.20-3.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php-odbc-debuginfo-8.0.20-3.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php-opcache-8.0.20-3.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php-opcache-8.0.20-3.el9', 'cpu':'i686', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php-opcache-8.0.20-3.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php-opcache-debuginfo-8.0.20-3.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php-opcache-debuginfo-8.0.20-3.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php-pdo-8.0.20-3.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php-pdo-8.0.20-3.el9', 'cpu':'i686', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php-pdo-8.0.20-3.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php-pdo-debuginfo-8.0.20-3.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php-pdo-debuginfo-8.0.20-3.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php-pgsql-8.0.20-3.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php-pgsql-8.0.20-3.el9', 'cpu':'i686', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php-pgsql-8.0.20-3.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php-pgsql-debuginfo-8.0.20-3.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php-pgsql-debuginfo-8.0.20-3.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php-process-8.0.20-3.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php-process-8.0.20-3.el9', 'cpu':'i686', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php-process-8.0.20-3.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php-process-debuginfo-8.0.20-3.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php-process-debuginfo-8.0.20-3.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php-snmp-8.0.20-3.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php-snmp-8.0.20-3.el9', 'cpu':'i686', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php-snmp-8.0.20-3.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php-snmp-debuginfo-8.0.20-3.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php-snmp-debuginfo-8.0.20-3.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php-soap-8.0.20-3.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php-soap-8.0.20-3.el9', 'cpu':'i686', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php-soap-8.0.20-3.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php-soap-debuginfo-8.0.20-3.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php-soap-debuginfo-8.0.20-3.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php-xml-8.0.20-3.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php-xml-8.0.20-3.el9', 'cpu':'i686', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php-xml-8.0.20-3.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php-xml-debuginfo-8.0.20-3.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php-xml-debuginfo-8.0.20-3.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE}
];

var flag = 0;
foreach var package_array ( pkgs ) {
  var reference = NULL;
  var _release = NULL;
  var sp = NULL;
  var _cpu = NULL;
  var el_string = NULL;
  var rpm_spec_vers_cmp = NULL;
  var epoch = NULL;
  var allowmaj = NULL;
  var exists_check = NULL;
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (!empty_or_null(package_array['release'])) _release = 'Rocky-' + package_array['release'];
  if (!empty_or_null(package_array['sp'])) sp = package_array['sp'];
  if (!empty_or_null(package_array['cpu'])) _cpu = package_array['cpu'];
  if (!empty_or_null(package_array['el_string'])) el_string = package_array['el_string'];
  if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
  if (!empty_or_null(package_array['epoch'])) epoch = package_array['epoch'];
  if (!empty_or_null(package_array['allowmaj'])) allowmaj = package_array['allowmaj'];
  if (!empty_or_null(package_array['exists_check'])) exists_check = package_array['exists_check'];
  if (reference && _release && (!exists_check || rpm_exists(release:_release, rpm:exists_check))) {
    if (rpm_check(release:_release, sp:sp, cpu:_cpu, reference:reference, epoch:epoch, el_string:el_string, rpm_spec_vers_cmp:rpm_spec_vers_cmp, allowmaj:allowmaj)) flag++;
  }
}

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'php / php-bcmath / php-bcmath-debuginfo / php-cli / php-cli-debuginfo / etc');
}
