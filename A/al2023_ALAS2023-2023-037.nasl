#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux 2023 Security Advisory ALAS2023-2023-037.
##

include('compat.inc');

if (description)
{
  script_id(173101);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/21");

  script_cve_id(
    "CVE-2021-2372",
    "CVE-2021-2389",
    "CVE-2021-35604",
    "CVE-2021-46658",
    "CVE-2021-46659",
    "CVE-2021-46661",
    "CVE-2021-46662",
    "CVE-2021-46663",
    "CVE-2021-46664",
    "CVE-2021-46665",
    "CVE-2021-46667",
    "CVE-2021-46668",
    "CVE-2021-46669",
    "CVE-2022-0778",
    "CVE-2022-24048",
    "CVE-2022-24050",
    "CVE-2022-24051",
    "CVE-2022-24052",
    "CVE-2022-27376",
    "CVE-2022-27377",
    "CVE-2022-27378",
    "CVE-2022-27379",
    "CVE-2022-27380",
    "CVE-2022-27381",
    "CVE-2022-27382",
    "CVE-2022-27383",
    "CVE-2022-27384",
    "CVE-2022-27385",
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
    "CVE-2022-31624",
    "CVE-2022-32081",
    "CVE-2022-32082",
    "CVE-2022-32083",
    "CVE-2022-32084",
    "CVE-2022-32085",
    "CVE-2022-32086",
    "CVE-2022-32087",
    "CVE-2022-32088",
    "CVE-2022-32089"
  );

  script_name(english:"Amazon Linux 2023 : mariadb105, mariadb105-backup, mariadb105-common (ALAS2023-2023-037)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Amazon Linux 2023 host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"It is, therefore, affected by multiple vulnerabilities as referenced in the ALAS2023-2023-037 advisory.

  - Vulnerability in the MySQL Server product of Oracle MySQL (component: InnoDB). Supported versions that are
    affected are 5.7.34 and prior and 8.0.25 and prior. Difficult to exploit vulnerability allows high
    privileged attacker with network access via multiple protocols to compromise MySQL Server. Successful
    attacks of this vulnerability can result in unauthorized ability to cause a hang or frequently repeatable
    crash (complete DOS) of MySQL Server. (CVE-2021-2372)

  - Vulnerability in the MySQL Server product of Oracle MySQL (component: InnoDB). Supported versions that are
    affected are 5.7.34 and prior and 8.0.25 and prior. Difficult to exploit vulnerability allows
    unauthenticated attacker with network access via multiple protocols to compromise MySQL Server. Successful
    attacks of this vulnerability can result in unauthorized ability to cause a hang or frequently repeatable
    crash (complete DOS) of MySQL Server. (CVE-2021-2389)

  - Vulnerability in the MySQL Server product of Oracle MySQL (component: InnoDB). Supported versions that are
    affected are 5.7.35 and prior and 8.0.26 and prior. Easily exploitable vulnerability allows high
    privileged attacker with network access via multiple protocols to compromise MySQL Server. Successful
    attacks of this vulnerability can result in unauthorized ability to cause a hang or frequently repeatable
    crash (complete DOS) of MySQL Server as well as unauthorized update, insert or delete access to some of
    MySQL Server accessible data. (CVE-2021-35604)

  - save_window_function_values in MariaDB before 10.6.3 allows an application crash because of incorrect
    handling of with_window_func=true for a subquery. (CVE-2021-46658)

  - MariaDB before 10.7.2 allows an application crash because it does not recognize that
    SELECT_LEX::nest_level is local to each VIEW. (CVE-2021-46659)

  - MariaDB through 10.5.9 allows an application crash in find_field_in_tables and find_order_in_list via an
    unused common table expression (CTE). (CVE-2021-46661)

  - MariaDB through 10.5.9 allows a set_var.cc application crash via certain uses of an UPDATE statement in
    conjunction with a nested subquery. (CVE-2021-46662)

  - MariaDB through 10.5.13 allows a ha_maria::extra application crash via certain SELECT statements.
    (CVE-2021-46663)

  - MariaDB through 10.5.9 allows an application crash in sub_select_postjoin_aggr for a NULL value of aggr.
    (CVE-2021-46664)

  - MariaDB through 10.5.9 allows a sql_parse.cc application crash because of incorrect used_tables
    expectations. (CVE-2021-46665)

  - MariaDB before 10.6.5 has a sql_lex.cc integer overflow, leading to an application crash. (CVE-2021-46667)

  - MariaDB through 10.5.9 allows an application crash via certain long SELECT DISTINCT statements that
    improperly interact with storage-engine resource limitations for temporary data structures.
    (CVE-2021-46668)

  - MariaDB through 10.5.9 allows attackers to trigger a convert_const_to_int use-after-free when the BIGINT
    data type is used. (CVE-2021-46669)

  - The BN_mod_sqrt() function, which computes a modular square root, contains a bug that can cause it to loop
    forever for non-prime moduli. Internally this function is used when parsing certificates that contain
    elliptic curve public keys in compressed form or explicit elliptic curve parameters with a base point
    encoded in compressed form. It is possible to trigger the infinite loop by crafting a certificate that has
    invalid explicit curve parameters. Since certificate parsing happens prior to verification of the
    certificate signature, any process that parses an externally supplied certificate may thus be subject to a
    denial of service attack. The infinite loop can also be reached when parsing crafted private keys as they
    can contain explicit elliptic curve parameters. Thus vulnerable situations include: - TLS clients
    consuming server certificates - TLS servers consuming client certificates - Hosting providers taking
    certificates or private keys from customers - Certificate authorities parsing certification requests from
    subscribers - Anything else which parses ASN.1 elliptic curve parameters Also any other applications that
    use the BN_mod_sqrt() where the attacker can control the parameter values are vulnerable to this DoS
    issue. In the OpenSSL 1.0.2 version the public key is not parsed during initial parsing of the certificate
    which makes it slightly harder to trigger the infinite loop. However any operation which requires the
    public key from the certificate will trigger the infinite loop. In particular the attacker can use a self-
    signed certificate to trigger the loop during verification of the certificate signature. This issue
    affects OpenSSL versions 1.0.2, 1.1.1 and 3.0. It was addressed in the releases of 1.1.1n and 3.0.2 on the
    15th March 2022. Fixed in OpenSSL 3.0.2 (Affected 3.0.0,3.0.1). Fixed in OpenSSL 1.1.1n (Affected
    1.1.1-1.1.1m). Fixed in OpenSSL 1.0.2zd (Affected 1.0.2-1.0.2zc). (CVE-2022-0778)

  - MariaDB CONNECT Storage Engine Stack-based Buffer Overflow Privilege Escalation Vulnerability. This
    vulnerability allows local attackers to escalate privileges on affected installations of MariaDB.
    Authentication is required to exploit this vulnerability. The specific flaw exists within the processing
    of SQL queries. The issue results from the lack of proper validation of the length of user-supplied data
    prior to copying it to a fixed-length stack-based buffer. An attacker can leverage this vulnerability to
    escalate privileges and execute arbitrary code in the context of the service account. Was ZDI-CAN-16191.
    (CVE-2022-24048)

  - MariaDB CONNECT Storage Engine Use-After-Free Privilege Escalation Vulnerability. This vulnerability
    allows local attackers to escalate privileges on affected installations of MariaDB. Authentication is
    required to exploit this vulnerability. The specific flaw exists within the processing of SQL queries. The
    issue results from the lack of validating the existence of an object prior to performing operations on the
    object. An attacker can leverage this vulnerability to escalate privileges and execute arbitrary code in
    the context of the service account. Was ZDI-CAN-16207. (CVE-2022-24050)

  - MariaDB CONNECT Storage Engine Format String Privilege Escalation Vulnerability. This vulnerability allows
    local attackers to escalate privileges on affected installations of MariaDB. Authentication is required to
    exploit this vulnerability. The specific flaw exists within the processing of SQL queries. The issue
    results from the lack of proper validation of a user-supplied string before using it as a format
    specifier. An attacker can leverage this vulnerability to escalate privileges and execute arbitrary code
    in the context of the service account. Was ZDI-CAN-16193. (CVE-2022-24051)

  - MariaDB CONNECT Storage Engine Heap-based Buffer Overflow Privilege Escalation Vulnerability. This
    vulnerability allows local attackers to escalate privileges on affected installations of MariaDB.
    Authentication is required to exploit this vulnerability. The specific flaw exists within the processing
    of SQL queries. The issue results from the lack of proper validation of the length of user-supplied data
    prior to copying it to a fixed-length heap-based buffer. An attacker can leverage this vulnerability to
    escalate privileges and execute arbitrary code in the context of the service account. Was ZDI-CAN-16190.
    (CVE-2022-24052)

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

  - An issue in the component Used_tables_and_const_cache::used_tables_and_const_cache_join of MariaDB Server
    v10.7 and below was discovered to allow attackers to cause a Denial of Service (DoS) via specially crafted
    SQL statements. (CVE-2022-27385)

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

  - MariaDB Server before 10.7 is vulnerable to Denial of Service. While executing the
    plugin/server_audit/server_audit.c method log_statement_ex, the held lock lock_bigbuffer is not released
    correctly, which allows local users to trigger a denial of service due to the deadlock. (CVE-2022-31624)

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

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/AL2023/ALAS-2023-037.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-2372.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-2389.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-35604.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-46658.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-46659.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-46661.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-46662.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-46663.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-46664.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-46665.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-46667.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-46668.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-46669.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-0778.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-24048.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-24050.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-24051.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-24052.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-27376.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-27377.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-27378.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-27379.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-27380.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-27381.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-27382.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-27383.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-27384.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-27385.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-27386.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-27387.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-27444.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-27445.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-27446.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-27447.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-27448.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-27449.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-27451.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-27452.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-27455.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-27456.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-27457.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-27458.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-31624.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-32081.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-32082.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-32083.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-32084.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-32085.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-32086.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-32087.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-32088.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-32089.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/faqs.html");
  script_set_attribute(attribute:"solution", value:
"Run 'dnf update mariadb105 --releasever=2023.0.20230222 ' to update your system.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-32081");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2022-24052");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/07/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/02/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/03/21");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:mariadb105");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:mariadb105-backup");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:mariadb105-backup-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:mariadb105-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:mariadb105-connect-engine");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:mariadb105-connect-engine-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:mariadb105-cracklib-password-check");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:mariadb105-cracklib-password-check-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:mariadb105-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:mariadb105-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:mariadb105-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:mariadb105-errmsg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:mariadb105-gssapi-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:mariadb105-gssapi-server-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:mariadb105-oqgraph-engine");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:mariadb105-oqgraph-engine-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:mariadb105-pam");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:mariadb105-pam-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:mariadb105-rocksdb-engine");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:mariadb105-rocksdb-engine-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:mariadb105-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:mariadb105-server-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:mariadb105-server-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:mariadb105-server-utils-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:mariadb105-sphinx-engine");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:mariadb105-sphinx-engine-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:mariadb105-test");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:mariadb105-test-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux:2023");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Amazon Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/AmazonLinux/release", "Host/AmazonLinux/rpm-list");

  exit(0);
}

include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

var alas_release = get_kb_item("Host/AmazonLinux/release");
if (isnull(alas_release) || !strlen(alas_release)) audit(AUDIT_OS_NOT, "Amazon Linux");
var os_ver = pregmatch(pattern: "^AL(A|\d+|-\d+)", string:alas_release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Amazon Linux");
os_ver = os_ver[1];
if (os_ver != "-2023")
{
  if (os_ver == 'A') os_ver = 'AMI';
  audit(AUDIT_OS_NOT, "Amazon Linux 2023", "Amazon Linux " + os_ver);
}

if (!get_kb_item("Host/AmazonLinux/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var pkgs = [
    {'reference':'mariadb105-10.5.16-1.amzn2023.0.7', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'mariadb105-10.5.16-1.amzn2023.0.7', 'cpu':'i686', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'mariadb105-10.5.16-1.amzn2023.0.7', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'mariadb105-backup-10.5.16-1.amzn2023.0.7', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'mariadb105-backup-10.5.16-1.amzn2023.0.7', 'cpu':'i686', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'mariadb105-backup-10.5.16-1.amzn2023.0.7', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'mariadb105-backup-debuginfo-10.5.16-1.amzn2023.0.7', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'mariadb105-backup-debuginfo-10.5.16-1.amzn2023.0.7', 'cpu':'i686', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'mariadb105-backup-debuginfo-10.5.16-1.amzn2023.0.7', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'mariadb105-common-10.5.16-1.amzn2023.0.7', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'mariadb105-common-10.5.16-1.amzn2023.0.7', 'cpu':'i686', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'mariadb105-common-10.5.16-1.amzn2023.0.7', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'mariadb105-connect-engine-10.5.16-1.amzn2023.0.7', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'mariadb105-connect-engine-10.5.16-1.amzn2023.0.7', 'cpu':'i686', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'mariadb105-connect-engine-10.5.16-1.amzn2023.0.7', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'mariadb105-connect-engine-debuginfo-10.5.16-1.amzn2023.0.7', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'mariadb105-connect-engine-debuginfo-10.5.16-1.amzn2023.0.7', 'cpu':'i686', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'mariadb105-connect-engine-debuginfo-10.5.16-1.amzn2023.0.7', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'mariadb105-cracklib-password-check-10.5.16-1.amzn2023.0.7', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'mariadb105-cracklib-password-check-10.5.16-1.amzn2023.0.7', 'cpu':'i686', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'mariadb105-cracklib-password-check-10.5.16-1.amzn2023.0.7', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'mariadb105-cracklib-password-check-debuginfo-10.5.16-1.amzn2023.0.7', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'mariadb105-cracklib-password-check-debuginfo-10.5.16-1.amzn2023.0.7', 'cpu':'i686', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'mariadb105-cracklib-password-check-debuginfo-10.5.16-1.amzn2023.0.7', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'mariadb105-debuginfo-10.5.16-1.amzn2023.0.7', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'mariadb105-debuginfo-10.5.16-1.amzn2023.0.7', 'cpu':'i686', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'mariadb105-debuginfo-10.5.16-1.amzn2023.0.7', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'mariadb105-debugsource-10.5.16-1.amzn2023.0.7', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'mariadb105-debugsource-10.5.16-1.amzn2023.0.7', 'cpu':'i686', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'mariadb105-debugsource-10.5.16-1.amzn2023.0.7', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'mariadb105-devel-10.5.16-1.amzn2023.0.7', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'mariadb105-devel-10.5.16-1.amzn2023.0.7', 'cpu':'i686', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'mariadb105-devel-10.5.16-1.amzn2023.0.7', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'mariadb105-errmsg-10.5.16-1.amzn2023.0.7', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'mariadb105-errmsg-10.5.16-1.amzn2023.0.7', 'cpu':'i686', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'mariadb105-errmsg-10.5.16-1.amzn2023.0.7', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'mariadb105-gssapi-server-10.5.16-1.amzn2023.0.7', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'mariadb105-gssapi-server-10.5.16-1.amzn2023.0.7', 'cpu':'i686', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'mariadb105-gssapi-server-10.5.16-1.amzn2023.0.7', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'mariadb105-gssapi-server-debuginfo-10.5.16-1.amzn2023.0.7', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'mariadb105-gssapi-server-debuginfo-10.5.16-1.amzn2023.0.7', 'cpu':'i686', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'mariadb105-gssapi-server-debuginfo-10.5.16-1.amzn2023.0.7', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'mariadb105-oqgraph-engine-10.5.16-1.amzn2023.0.7', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'mariadb105-oqgraph-engine-10.5.16-1.amzn2023.0.7', 'cpu':'i686', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'mariadb105-oqgraph-engine-10.5.16-1.amzn2023.0.7', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'mariadb105-oqgraph-engine-debuginfo-10.5.16-1.amzn2023.0.7', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'mariadb105-oqgraph-engine-debuginfo-10.5.16-1.amzn2023.0.7', 'cpu':'i686', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'mariadb105-oqgraph-engine-debuginfo-10.5.16-1.amzn2023.0.7', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'mariadb105-pam-10.5.16-1.amzn2023.0.7', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'mariadb105-pam-10.5.16-1.amzn2023.0.7', 'cpu':'i686', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'mariadb105-pam-10.5.16-1.amzn2023.0.7', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'mariadb105-pam-debuginfo-10.5.16-1.amzn2023.0.7', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'mariadb105-pam-debuginfo-10.5.16-1.amzn2023.0.7', 'cpu':'i686', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'mariadb105-pam-debuginfo-10.5.16-1.amzn2023.0.7', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'mariadb105-rocksdb-engine-10.5.16-1.amzn2023.0.7', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'mariadb105-rocksdb-engine-debuginfo-10.5.16-1.amzn2023.0.7', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'mariadb105-server-10.5.16-1.amzn2023.0.7', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'mariadb105-server-10.5.16-1.amzn2023.0.7', 'cpu':'i686', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'mariadb105-server-10.5.16-1.amzn2023.0.7', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'mariadb105-server-debuginfo-10.5.16-1.amzn2023.0.7', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'mariadb105-server-debuginfo-10.5.16-1.amzn2023.0.7', 'cpu':'i686', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'mariadb105-server-debuginfo-10.5.16-1.amzn2023.0.7', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'mariadb105-server-utils-10.5.16-1.amzn2023.0.7', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'mariadb105-server-utils-10.5.16-1.amzn2023.0.7', 'cpu':'i686', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'mariadb105-server-utils-10.5.16-1.amzn2023.0.7', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'mariadb105-server-utils-debuginfo-10.5.16-1.amzn2023.0.7', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'mariadb105-server-utils-debuginfo-10.5.16-1.amzn2023.0.7', 'cpu':'i686', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'mariadb105-server-utils-debuginfo-10.5.16-1.amzn2023.0.7', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'mariadb105-sphinx-engine-10.5.16-1.amzn2023.0.7', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'mariadb105-sphinx-engine-10.5.16-1.amzn2023.0.7', 'cpu':'i686', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'mariadb105-sphinx-engine-10.5.16-1.amzn2023.0.7', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'mariadb105-sphinx-engine-debuginfo-10.5.16-1.amzn2023.0.7', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'mariadb105-sphinx-engine-debuginfo-10.5.16-1.amzn2023.0.7', 'cpu':'i686', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'mariadb105-sphinx-engine-debuginfo-10.5.16-1.amzn2023.0.7', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'mariadb105-test-10.5.16-1.amzn2023.0.7', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'mariadb105-test-10.5.16-1.amzn2023.0.7', 'cpu':'i686', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'mariadb105-test-10.5.16-1.amzn2023.0.7', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'mariadb105-test-debuginfo-10.5.16-1.amzn2023.0.7', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'mariadb105-test-debuginfo-10.5.16-1.amzn2023.0.7', 'cpu':'i686', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'mariadb105-test-debuginfo-10.5.16-1.amzn2023.0.7', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE}
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
  if (!empty_or_null(package_array['release'])) _release = package_array['release'];
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
      severity   : SECURITY_HOLE,
      extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "mariadb105 / mariadb105-backup / mariadb105-backup-debuginfo / etc");
}