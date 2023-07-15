#%NASL_MIN_LEVEL 80900
#
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dla-3114. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('compat.inc');

if (description)
{
  script_id(165219);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/09/16");

  script_cve_id(
    "CVE-2018-25032",
    "CVE-2021-46669",
    "CVE-2022-21427",
    "CVE-2022-27376",
    "CVE-2022-27377",
    "CVE-2022-27378",
    "CVE-2022-27379",
    "CVE-2022-27380",
    "CVE-2022-27381",
    "CVE-2022-27383",
    "CVE-2022-27384",
    "CVE-2022-27386",
    "CVE-2022-27387",
    "CVE-2022-27445",
    "CVE-2022-27447",
    "CVE-2022-27448",
    "CVE-2022-27449",
    "CVE-2022-27452",
    "CVE-2022-27456",
    "CVE-2022-27458",
    "CVE-2022-32083",
    "CVE-2022-32084",
    "CVE-2022-32085",
    "CVE-2022-32087",
    "CVE-2022-32088",
    "CVE-2022-32091"
  );

  script_name(english:"Debian DLA-3114-1 : mariadb-10.3 - LTS security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 10 host has packages installed that are affected by multiple vulnerabilities as referenced in the
dla-3114 advisory.

  - zlib before 1.2.12 allows memory corruption when deflating (i.e., when compressing) if the input has many
    distant matches. (CVE-2018-25032)

  - MariaDB through 10.5.9 allows attackers to trigger a convert_const_to_int use-after-free when the BIGINT
    data type is used. (CVE-2021-46669)

  - Vulnerability in the MySQL Server product of Oracle MySQL (component: Server: FTS). Supported versions
    that are affected are 5.7.37 and prior and 8.0.28 and prior. Easily exploitable vulnerability allows high
    privileged attacker with network access via multiple protocols to compromise MySQL Server. Successful
    attacks of this vulnerability can result in unauthorized ability to cause a hang or frequently repeatable
    crash (complete DOS) of MySQL Server. CVSS 3.1 Base Score 4.9 (Availability impacts). CVSS Vector:
    (CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:N/I:N/A:H). (CVE-2022-21427)

  - MariaDB Server v10.6.5 and below was discovered to contain an use-after-free in the component
    Item_args::walk_arg, which is exploited via specially crafted SQL statements. (CVE-2022-27376)

  - MariaDB Server v10.6.3 and below was discovered to contain an use-after-free in the component
    Item_func_in::cleanup(), which is exploited via specially crafted SQL statements. (CVE-2022-27377)

  - An issue in the component Create_tmp_table::finalize of MariaDB Server v10.7 and below was discovered to
    allow attackers to cause a Denial of Service (DoS) via specially crafted SQL statements. (CVE-2022-27378)

  - An issue in the component Arg_comparator::compare_real_fixed of MariaDB Server v10.6.2 and below was
    discovered to allow attackers to cause a Denial of Service (DoS) via specially crafted SQL statements.
    (CVE-2022-27379)

  - An issue in the component my_decimal::operator= of MariaDB Server v10.6.3 and below was discovered to
    allow attackers to cause a Denial of Service (DoS) via specially crafted SQL statements. (CVE-2022-27380)

  - An issue in the component Field::set_default of MariaDB Server v10.6 and below was discovered to allow
    attackers to cause a Denial of Service (DoS) via specially crafted SQL statements. (CVE-2022-27381)

  - MariaDB Server v10.6 and below was discovered to contain an use-after-free in the component
    my_strcasecmp_8bit, which is exploited via specially crafted SQL statements. (CVE-2022-27383)

  - An issue in the component Item_subselect::init_expr_cache_tracker of MariaDB Server v10.6 and below was
    discovered to allow attackers to cause a Denial of Service (DoS) via specially crafted SQL statements.
    (CVE-2022-27384)

  - MariaDB Server v10.7 and below was discovered to contain a segmentation fault via the component
    sql/sql_class.cc. (CVE-2022-27386)

  - MariaDB Server v10.7 and below was discovered to contain a global buffer overflow in the component
    decimal_bin_size, which is exploited via specially crafted SQL statements. (CVE-2022-27387)

  - MariaDB Server v10.9 and below was discovered to contain a segmentation fault via the component
    sql/sql_window.cc. (CVE-2022-27445)

  - MariaDB Server v10.9 and below was discovered to contain a use-after-free via the component
    Binary_string::free_buffer() at /sql/sql_string.h. (CVE-2022-27447)

  - There is an Assertion failure in MariaDB Server v10.9 and below via 'node->pcur->rel_pos == BTR_PCUR_ON'
    at /row/row0mysql.cc. (CVE-2022-27448)

  - MariaDB Server v10.9 and below was discovered to contain a segmentation fault via the component
    sql/item_func.cc:148. (CVE-2022-27449)

  - MariaDB Server v10.9 and below was discovered to contain a segmentation fault via the component
    sql/item_cmpfunc.cc. (CVE-2022-27452)

  - MariaDB Server v10.6.3 and below was discovered to contain an use-after-free in the component VDec::VDec
    at /sql/sql_type.cc. (CVE-2022-27456)

  - MariaDB Server v10.6.3 and below was discovered to contain an use-after-free in the component
    Binary_string::free_buffer() at /sql/sql_string.h. (CVE-2022-27458)

  - MariaDB v10.2 to v10.6.1 was discovered to contain a segmentation fault via the component
    Item_subselect::init_expr_cache_tracker. (CVE-2022-32083)

  - MariaDB v10.2 to v10.7 was discovered to contain a segmentation fault via the component sub_select.
    (CVE-2022-32084)

  - MariaDB v10.2 to v10.7 was discovered to contain a segmentation fault via the component
    Item_func_in::cleanup/Item::cleanup_processor. (CVE-2022-32085)

  - MariaDB v10.2 to v10.7 was discovered to contain a segmentation fault via the component
    Item_args::walk_args. (CVE-2022-32087)

  - MariaDB v10.2 to v10.7 was discovered to contain a segmentation fault via the component
    Exec_time_tracker::get_loops/Filesort_tracker::report_use/filesort. (CVE-2022-32088)

  - MariaDB v10.7 was discovered to contain an use-after-poison in in __interceptor_memset at
    /libsanitizer/sanitizer_common/sanitizer_common_interceptors.inc. (CVE-2022-32091)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://security-tracker.debian.org/tracker/source-package/mariadb-10.3
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?cb6537b5");
  script_set_attribute(attribute:"see_also", value:"https://www.debian.org/lts/security/2022/dla-3114");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2018-25032");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-46669");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-21427");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-27376");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-27377");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-27378");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-27379");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-27380");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-27381");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-27383");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-27384");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-27386");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-27387");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-27445");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-27447");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-27448");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-27449");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-27452");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-27456");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-27458");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-32083");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-32084");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-32085");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-32087");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-32088");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-32091");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/buster/mariadb-10.3");
  script_set_attribute(attribute:"solution", value:
"Upgrade the mariadb-10.3 packages.

For Debian 10 buster, these problems have been fixed in version 1");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-32091");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/02/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/09/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/09/16");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmariadb-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmariadb-dev-compat");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmariadb3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmariadbclient-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmariadbd-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmariadbd19");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mariadb-backup");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mariadb-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mariadb-client-10.3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mariadb-client-core-10.3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mariadb-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mariadb-plugin-connect");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mariadb-plugin-cracklib-password-check");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mariadb-plugin-gssapi-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mariadb-plugin-gssapi-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mariadb-plugin-mroonga");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mariadb-plugin-oqgraph");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mariadb-plugin-rocksdb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mariadb-plugin-spider");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mariadb-plugin-tokudb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mariadb-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mariadb-server-10.3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mariadb-server-core-10.3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mariadb-test");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mariadb-test-data");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:10.0");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Debian Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/Debian/release", "Host/Debian/dpkg-l");

  exit(0);
}

include('debian_package.inc');

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/Debian/dpkg-l")) audit(AUDIT_PACKAGE_LIST_MISSING);

var release = get_kb_item('Host/Debian/release');
if ( isnull(release) ) audit(AUDIT_OS_NOT, 'Debian');
var release = chomp(release);
if (! preg(pattern:"^(10)\.[0-9]+", string:release)) audit(AUDIT_OS_NOT, 'Debian 10.0', 'Debian ' + release);
var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Debian', cpu);

var pkgs = [
    {'release': '10.0', 'prefix': 'libmariadb-dev', 'reference': '1:10.3.36-0+deb10u1'},
    {'release': '10.0', 'prefix': 'libmariadb-dev-compat', 'reference': '1:10.3.36-0+deb10u1'},
    {'release': '10.0', 'prefix': 'libmariadb3', 'reference': '1:10.3.36-0+deb10u1'},
    {'release': '10.0', 'prefix': 'libmariadbclient-dev', 'reference': '1:10.3.36-0+deb10u1'},
    {'release': '10.0', 'prefix': 'libmariadbd-dev', 'reference': '1:10.3.36-0+deb10u1'},
    {'release': '10.0', 'prefix': 'libmariadbd19', 'reference': '1:10.3.36-0+deb10u1'},
    {'release': '10.0', 'prefix': 'mariadb-backup', 'reference': '1:10.3.36-0+deb10u1'},
    {'release': '10.0', 'prefix': 'mariadb-client', 'reference': '1:10.3.36-0+deb10u1'},
    {'release': '10.0', 'prefix': 'mariadb-client-10.3', 'reference': '1:10.3.36-0+deb10u1'},
    {'release': '10.0', 'prefix': 'mariadb-client-core-10.3', 'reference': '1:10.3.36-0+deb10u1'},
    {'release': '10.0', 'prefix': 'mariadb-common', 'reference': '1:10.3.36-0+deb10u1'},
    {'release': '10.0', 'prefix': 'mariadb-plugin-connect', 'reference': '1:10.3.36-0+deb10u1'},
    {'release': '10.0', 'prefix': 'mariadb-plugin-cracklib-password-check', 'reference': '1:10.3.36-0+deb10u1'},
    {'release': '10.0', 'prefix': 'mariadb-plugin-gssapi-client', 'reference': '1:10.3.36-0+deb10u1'},
    {'release': '10.0', 'prefix': 'mariadb-plugin-gssapi-server', 'reference': '1:10.3.36-0+deb10u1'},
    {'release': '10.0', 'prefix': 'mariadb-plugin-mroonga', 'reference': '1:10.3.36-0+deb10u1'},
    {'release': '10.0', 'prefix': 'mariadb-plugin-oqgraph', 'reference': '1:10.3.36-0+deb10u1'},
    {'release': '10.0', 'prefix': 'mariadb-plugin-rocksdb', 'reference': '1:10.3.36-0+deb10u1'},
    {'release': '10.0', 'prefix': 'mariadb-plugin-spider', 'reference': '1:10.3.36-0+deb10u1'},
    {'release': '10.0', 'prefix': 'mariadb-plugin-tokudb', 'reference': '1:10.3.36-0+deb10u1'},
    {'release': '10.0', 'prefix': 'mariadb-server', 'reference': '1:10.3.36-0+deb10u1'},
    {'release': '10.0', 'prefix': 'mariadb-server-10.3', 'reference': '1:10.3.36-0+deb10u1'},
    {'release': '10.0', 'prefix': 'mariadb-server-core-10.3', 'reference': '1:10.3.36-0+deb10u1'},
    {'release': '10.0', 'prefix': 'mariadb-test', 'reference': '1:10.3.36-0+deb10u1'},
    {'release': '10.0', 'prefix': 'mariadb-test-data', 'reference': '1:10.3.36-0+deb10u1'}
];

var flag = 0;
foreach package_array ( pkgs ) {
  var release = NULL;
  var prefix = NULL;
  var reference = NULL;
  if (!empty_or_null(package_array['release'])) release = package_array['release'];
  if (!empty_or_null(package_array['prefix'])) prefix = package_array['prefix'];
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (release && prefix && reference) {
    if (deb_check(release:release, prefix:prefix, reference:reference)) flag++;
  }
}

if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_WARNING,
    extra      : deb_report_get()
  );
  exit(0);
}
else
{
  var tested = deb_pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'libmariadb-dev / libmariadb-dev-compat / libmariadb3 / etc');
}
