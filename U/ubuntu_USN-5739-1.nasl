#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-5739-1. The text
# itself is copyright (C) Canonical, Inc. See
# <https://ubuntu.com/security/notices>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('compat.inc');

if (description)
{
  script_id(168154);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/07/10");

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
    "CVE-2022-27382",
    "CVE-2022-27383",
    "CVE-2022-27384",
    "CVE-2022-27386",
    "CVE-2022-27387",
    "CVE-2022-27444",
    "CVE-2022-27445",
    "CVE-2022-27446",
    "CVE-2022-27447",
    "CVE-2022-27448",
    "CVE-2022-27449",
    "CVE-2022-27451",
    "CVE-2022-27452",
    "CVE-2022-27455",
    "CVE-2022-27456",
    "CVE-2022-27457",
    "CVE-2022-27458",
    "CVE-2022-32081",
    "CVE-2022-32082",
    "CVE-2022-32083",
    "CVE-2022-32084",
    "CVE-2022-32085",
    "CVE-2022-32086",
    "CVE-2022-32087",
    "CVE-2022-32088",
    "CVE-2022-32089",
    "CVE-2022-32091"
  );
  script_xref(name:"USN", value:"5739-1");

  script_name(english:"Ubuntu 20.04 LTS / 22.04 LTS / 22.10 : MariaDB vulnerabilities (USN-5739-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 20.04 LTS / 22.04 LTS / 22.10 host has packages installed that are affected by multiple
vulnerabilities as referenced in the USN-5739-1 advisory.

  - zlib before 1.2.12 allows memory corruption when deflating (i.e., when compressing) if the input has many
    distant matches. (CVE-2018-25032)

  - MariaDB through 10.5.9 allows attackers to trigger a convert_const_to_int use-after-free when the BIGINT
    data type is used. (CVE-2021-46669)

  - Vulnerability in the MySQL Server product of Oracle MySQL (component: Server: FTS). Supported versions
    that are affected are 5.7.37 and prior and 8.0.28 and prior. Easily exploitable vulnerability allows high
    privileged attacker with network access via multiple protocols to compromise MySQL Server. Successful
    attacks of this vulnerability can result in unauthorized ability to cause a hang or frequently repeatable
    crash (complete DOS) of MySQL Server. (CVE-2022-21427)

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

  - MariaDB Server v10.7 and below was discovered to contain a segmentation fault via the component
    Item_field::used_tables/update_depend_map_for_order. (CVE-2022-27382)

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
    sql/item_subselect.cc. (CVE-2022-27444)

  - MariaDB Server v10.9 and below was discovered to contain a segmentation fault via the component
    sql/sql_window.cc. (CVE-2022-27445)

  - MariaDB Server v10.9 and below was discovered to contain a segmentation fault via the component
    sql/item_cmpfunc.h. (CVE-2022-27446)

  - MariaDB Server v10.9 and below was discovered to contain a use-after-free via the component
    Binary_string::free_buffer() at /sql/sql_string.h. (CVE-2022-27447)

  - There is an Assertion failure in MariaDB Server v10.9 and below via 'node->pcur->rel_pos == BTR_PCUR_ON'
    at /row/row0mysql.cc. (CVE-2022-27448)

  - MariaDB Server v10.9 and below was discovered to contain a segmentation fault via the component
    sql/item_func.cc:148. (CVE-2022-27449)

  - MariaDB Server v10.9 and below was discovered to contain a segmentation fault via the component
    sql/field_conv.cc. (CVE-2022-27451)

  - MariaDB Server v10.9 and below was discovered to contain a segmentation fault via the component
    sql/item_cmpfunc.cc. (CVE-2022-27452)

  - MariaDB Server v10.6.3 and below was discovered to contain an use-after-free in the component
    my_wildcmp_8bit_impl at /strings/ctype-simple.c. (CVE-2022-27455)

  - MariaDB Server v10.6.3 and below was discovered to contain an use-after-free in the component VDec::VDec
    at /sql/sql_type.cc. (CVE-2022-27456)

  - MariaDB Server v10.6.3 and below was discovered to contain an use-after-free in the component
    my_mb_wc_latin1 at /strings/ctype-latin1.c. (CVE-2022-27457)

  - MariaDB Server v10.6.3 and below was discovered to contain an use-after-free in the component
    Binary_string::free_buffer() at /sql/sql_string.h. (CVE-2022-27458)

  - MariaDB v10.4 to v10.7 was discovered to contain an use-after-poison in prepare_inplace_add_virtual at
    /storage/innobase/handler/handler0alter.cc. (CVE-2022-32081)

  - MariaDB v10.5 to v10.7 was discovered to contain an assertion failure at table->get_ref_count() == 0 in
    dict0dict.cc. (CVE-2022-32082)

  - MariaDB v10.2 to v10.6.1 was discovered to contain a segmentation fault via the component
    Item_subselect::init_expr_cache_tracker. (CVE-2022-32083)

  - MariaDB v10.2 to v10.7 was discovered to contain a segmentation fault via the component sub_select.
    (CVE-2022-32084)

  - MariaDB v10.2 to v10.7 was discovered to contain a segmentation fault via the component
    Item_func_in::cleanup/Item::cleanup_processor. (CVE-2022-32085)

  - MariaDB v10.4 to v10.8 was discovered to contain a segmentation fault via the component
    Item_field::fix_outer_field. (CVE-2022-32086)

  - MariaDB v10.2 to v10.7 was discovered to contain a segmentation fault via the component
    Item_args::walk_args. (CVE-2022-32087)

  - MariaDB v10.2 to v10.7 was discovered to contain a segmentation fault via the component
    Exec_time_tracker::get_loops/Filesort_tracker::report_use/filesort. (CVE-2022-32088)

  - MariaDB v10.5 to v10.7 was discovered to contain a segmentation fault via the component
    st_select_lex_unit::exclude_level. (CVE-2022-32089)

  - MariaDB v10.7 was discovered to contain an use-after-poison in in __interceptor_memset at
    /libsanitizer/sanitizer_common/sanitizer_common_interceptors.inc. (CVE-2022-32091)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-5739-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-32081");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2022-32091");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/02/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/11/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/11/23");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:20.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:22.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:22.10");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmariadb-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmariadb-dev-compat");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmariadb3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmariadbclient-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmariadbd-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmariadbd19");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:mariadb-backup");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:mariadb-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:mariadb-client-10.3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:mariadb-client-10.6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:mariadb-client-core-10.3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:mariadb-client-core-10.6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:mariadb-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:mariadb-plugin-connect");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:mariadb-plugin-cracklib-password-check");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:mariadb-plugin-gssapi-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:mariadb-plugin-gssapi-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:mariadb-plugin-mroonga");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:mariadb-plugin-oqgraph");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:mariadb-plugin-rocksdb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:mariadb-plugin-s3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:mariadb-plugin-spider");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:mariadb-plugin-tokudb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:mariadb-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:mariadb-server-10.3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:mariadb-server-10.6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:mariadb-server-core-10.3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:mariadb-server-core-10.6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:mariadb-test");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:mariadb-test-data");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Ubuntu Local Security Checks");

  script_copyright(english:"Ubuntu Security Notice (C) 2022-2023 Canonical, Inc. / NASL script (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/cpu", "Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

  exit(0);
}

include('debian_package.inc');

if ( ! get_kb_item('Host/local_checks_enabled') ) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item('Host/Ubuntu/release');
if ( isnull(os_release) ) audit(AUDIT_OS_NOT, 'Ubuntu');
os_release = chomp(os_release);
if (! ('20.04' >< os_release || '22.04' >< os_release || '22.10' >< os_release)) audit(AUDIT_OS_NOT, 'Ubuntu 20.04 / 22.04 / 22.10', 'Ubuntu ' + os_release);
if ( ! get_kb_item('Host/Debian/dpkg-l') ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);

var pkgs = [
    {'osver': '20.04', 'pkgname': 'libmariadb-dev', 'pkgver': '1:10.3.37-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'libmariadb-dev-compat', 'pkgver': '1:10.3.37-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'libmariadb3', 'pkgver': '1:10.3.37-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'libmariadbclient-dev', 'pkgver': '1:10.3.37-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'libmariadbd-dev', 'pkgver': '1:10.3.37-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'libmariadbd19', 'pkgver': '1:10.3.37-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'mariadb-backup', 'pkgver': '1:10.3.37-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'mariadb-client', 'pkgver': '1:10.3.37-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'mariadb-client-10.3', 'pkgver': '1:10.3.37-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'mariadb-client-core-10.3', 'pkgver': '1:10.3.37-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'mariadb-common', 'pkgver': '1:10.3.37-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'mariadb-plugin-connect', 'pkgver': '1:10.3.37-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'mariadb-plugin-cracklib-password-check', 'pkgver': '1:10.3.37-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'mariadb-plugin-gssapi-client', 'pkgver': '1:10.3.37-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'mariadb-plugin-gssapi-server', 'pkgver': '1:10.3.37-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'mariadb-plugin-mroonga', 'pkgver': '1:10.3.37-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'mariadb-plugin-oqgraph', 'pkgver': '1:10.3.37-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'mariadb-plugin-rocksdb', 'pkgver': '1:10.3.37-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'mariadb-plugin-spider', 'pkgver': '1:10.3.37-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'mariadb-plugin-tokudb', 'pkgver': '1:10.3.37-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'mariadb-server', 'pkgver': '1:10.3.37-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'mariadb-server-10.3', 'pkgver': '1:10.3.37-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'mariadb-server-core-10.3', 'pkgver': '1:10.3.37-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'mariadb-test', 'pkgver': '1:10.3.37-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'mariadb-test-data', 'pkgver': '1:10.3.37-0ubuntu0.20.04.1'},
    {'osver': '22.04', 'pkgname': 'libmariadb-dev', 'pkgver': '1:10.6.11-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'libmariadb-dev-compat', 'pkgver': '1:10.6.11-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'libmariadb3', 'pkgver': '1:10.6.11-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'libmariadbd-dev', 'pkgver': '1:10.6.11-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'libmariadbd19', 'pkgver': '1:10.6.11-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'mariadb-backup', 'pkgver': '1:10.6.11-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'mariadb-client', 'pkgver': '1:10.6.11-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'mariadb-client-10.6', 'pkgver': '1:10.6.11-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'mariadb-client-core-10.6', 'pkgver': '1:10.6.11-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'mariadb-common', 'pkgver': '1:10.6.11-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'mariadb-plugin-connect', 'pkgver': '1:10.6.11-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'mariadb-plugin-cracklib-password-check', 'pkgver': '1:10.6.11-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'mariadb-plugin-gssapi-client', 'pkgver': '1:10.6.11-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'mariadb-plugin-gssapi-server', 'pkgver': '1:10.6.11-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'mariadb-plugin-mroonga', 'pkgver': '1:10.6.11-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'mariadb-plugin-oqgraph', 'pkgver': '1:10.6.11-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'mariadb-plugin-rocksdb', 'pkgver': '1:10.6.11-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'mariadb-plugin-s3', 'pkgver': '1:10.6.11-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'mariadb-plugin-spider', 'pkgver': '1:10.6.11-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'mariadb-server', 'pkgver': '1:10.6.11-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'mariadb-server-10.6', 'pkgver': '1:10.6.11-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'mariadb-server-core-10.6', 'pkgver': '1:10.6.11-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'mariadb-test', 'pkgver': '1:10.6.11-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'mariadb-test-data', 'pkgver': '1:10.6.11-0ubuntu0.22.04.1'},
    {'osver': '22.10', 'pkgname': 'libmariadb-dev', 'pkgver': '1:10.6.11-0ubuntu0.22.10.1'},
    {'osver': '22.10', 'pkgname': 'libmariadb-dev-compat', 'pkgver': '1:10.6.11-0ubuntu0.22.10.1'},
    {'osver': '22.10', 'pkgname': 'libmariadb3', 'pkgver': '1:10.6.11-0ubuntu0.22.10.1'},
    {'osver': '22.10', 'pkgname': 'libmariadbd-dev', 'pkgver': '1:10.6.11-0ubuntu0.22.10.1'},
    {'osver': '22.10', 'pkgname': 'libmariadbd19', 'pkgver': '1:10.6.11-0ubuntu0.22.10.1'},
    {'osver': '22.10', 'pkgname': 'mariadb-backup', 'pkgver': '1:10.6.11-0ubuntu0.22.10.1'},
    {'osver': '22.10', 'pkgname': 'mariadb-client', 'pkgver': '1:10.6.11-0ubuntu0.22.10.1'},
    {'osver': '22.10', 'pkgname': 'mariadb-client-10.6', 'pkgver': '1:10.6.11-0ubuntu0.22.10.1'},
    {'osver': '22.10', 'pkgname': 'mariadb-client-core-10.6', 'pkgver': '1:10.6.11-0ubuntu0.22.10.1'},
    {'osver': '22.10', 'pkgname': 'mariadb-common', 'pkgver': '1:10.6.11-0ubuntu0.22.10.1'},
    {'osver': '22.10', 'pkgname': 'mariadb-plugin-connect', 'pkgver': '1:10.6.11-0ubuntu0.22.10.1'},
    {'osver': '22.10', 'pkgname': 'mariadb-plugin-cracklib-password-check', 'pkgver': '1:10.6.11-0ubuntu0.22.10.1'},
    {'osver': '22.10', 'pkgname': 'mariadb-plugin-gssapi-client', 'pkgver': '1:10.6.11-0ubuntu0.22.10.1'},
    {'osver': '22.10', 'pkgname': 'mariadb-plugin-gssapi-server', 'pkgver': '1:10.6.11-0ubuntu0.22.10.1'},
    {'osver': '22.10', 'pkgname': 'mariadb-plugin-mroonga', 'pkgver': '1:10.6.11-0ubuntu0.22.10.1'},
    {'osver': '22.10', 'pkgname': 'mariadb-plugin-oqgraph', 'pkgver': '1:10.6.11-0ubuntu0.22.10.1'},
    {'osver': '22.10', 'pkgname': 'mariadb-plugin-rocksdb', 'pkgver': '1:10.6.11-0ubuntu0.22.10.1'},
    {'osver': '22.10', 'pkgname': 'mariadb-plugin-s3', 'pkgver': '1:10.6.11-0ubuntu0.22.10.1'},
    {'osver': '22.10', 'pkgname': 'mariadb-plugin-spider', 'pkgver': '1:10.6.11-0ubuntu0.22.10.1'},
    {'osver': '22.10', 'pkgname': 'mariadb-server', 'pkgver': '1:10.6.11-0ubuntu0.22.10.1'},
    {'osver': '22.10', 'pkgname': 'mariadb-server-10.6', 'pkgver': '1:10.6.11-0ubuntu0.22.10.1'},
    {'osver': '22.10', 'pkgname': 'mariadb-server-core-10.6', 'pkgver': '1:10.6.11-0ubuntu0.22.10.1'},
    {'osver': '22.10', 'pkgname': 'mariadb-test', 'pkgver': '1:10.6.11-0ubuntu0.22.10.1'},
    {'osver': '22.10', 'pkgname': 'mariadb-test-data', 'pkgver': '1:10.6.11-0ubuntu0.22.10.1'}
];

var flag = 0;
foreach package_array ( pkgs ) {
  var osver = NULL;
  var pkgname = NULL;
  var pkgver = NULL;
  if (!empty_or_null(package_array['osver'])) osver = package_array['osver'];
  if (!empty_or_null(package_array['pkgname'])) pkgname = package_array['pkgname'];
  if (!empty_or_null(package_array['pkgver'])) pkgver = package_array['pkgver'];
  if (osver && pkgname && pkgver) {
    if (ubuntu_check(osver:osver, pkgname:pkgname, pkgver:pkgver)) flag++;
  }
}

if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_HOLE,
    extra      : ubuntu_report_get()
  );
  exit(0);
}
else
{
  var tested = ubuntu_pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'libmariadb-dev / libmariadb-dev-compat / libmariadb3 / etc');
}
