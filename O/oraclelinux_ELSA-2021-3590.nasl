#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Oracle Linux Security Advisory ELSA-2021-3590.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(153575);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/05");

  script_cve_id(
    "CVE-2020-14672",
    "CVE-2020-14765",
    "CVE-2020-14769",
    "CVE-2020-14773",
    "CVE-2020-14775",
    "CVE-2020-14776",
    "CVE-2020-14777",
    "CVE-2020-14785",
    "CVE-2020-14786",
    "CVE-2020-14789",
    "CVE-2020-14790",
    "CVE-2020-14791",
    "CVE-2020-14793",
    "CVE-2020-14794",
    "CVE-2020-14800",
    "CVE-2020-14804",
    "CVE-2020-14809",
    "CVE-2020-14812",
    "CVE-2020-14814",
    "CVE-2020-14821",
    "CVE-2020-14828",
    "CVE-2020-14829",
    "CVE-2020-14830",
    "CVE-2020-14836",
    "CVE-2020-14837",
    "CVE-2020-14838",
    "CVE-2020-14839",
    "CVE-2020-14844",
    "CVE-2020-14845",
    "CVE-2020-14846",
    "CVE-2020-14848",
    "CVE-2020-14852",
    "CVE-2020-14860",
    "CVE-2020-14861",
    "CVE-2020-14866",
    "CVE-2020-14867",
    "CVE-2020-14868",
    "CVE-2020-14870",
    "CVE-2020-14873",
    "CVE-2020-14888",
    "CVE-2020-14891",
    "CVE-2020-14893",
    "CVE-2021-2001",
    "CVE-2021-2002",
    "CVE-2021-2010",
    "CVE-2021-2011",
    "CVE-2021-2021",
    "CVE-2021-2022",
    "CVE-2021-2024",
    "CVE-2021-2028",
    "CVE-2021-2030",
    "CVE-2021-2031",
    "CVE-2021-2032",
    "CVE-2021-2036",
    "CVE-2021-2038",
    "CVE-2021-2042",
    "CVE-2021-2046",
    "CVE-2021-2048",
    "CVE-2021-2055",
    "CVE-2021-2056",
    "CVE-2021-2058",
    "CVE-2021-2060",
    "CVE-2021-2061",
    "CVE-2021-2065",
    "CVE-2021-2070",
    "CVE-2021-2072",
    "CVE-2021-2076",
    "CVE-2021-2081",
    "CVE-2021-2087",
    "CVE-2021-2088",
    "CVE-2021-2122",
    "CVE-2021-2146",
    "CVE-2021-2164",
    "CVE-2021-2166",
    "CVE-2021-2169",
    "CVE-2021-2170",
    "CVE-2021-2171",
    "CVE-2021-2172",
    "CVE-2021-2174",
    "CVE-2021-2178",
    "CVE-2021-2179",
    "CVE-2021-2180",
    "CVE-2021-2193",
    "CVE-2021-2194",
    "CVE-2021-2196",
    "CVE-2021-2201",
    "CVE-2021-2202",
    "CVE-2021-2203",
    "CVE-2021-2208",
    "CVE-2021-2212",
    "CVE-2021-2213",
    "CVE-2021-2215",
    "CVE-2021-2217",
    "CVE-2021-2226",
    "CVE-2021-2230",
    "CVE-2021-2232",
    "CVE-2021-2278",
    "CVE-2021-2293",
    "CVE-2021-2298",
    "CVE-2021-2299",
    "CVE-2021-2300",
    "CVE-2021-2301",
    "CVE-2021-2304",
    "CVE-2021-2305",
    "CVE-2021-2307",
    "CVE-2021-2308",
    "CVE-2021-2339",
    "CVE-2021-2340",
    "CVE-2021-2342",
    "CVE-2021-2352",
    "CVE-2021-2354",
    "CVE-2021-2356",
    "CVE-2021-2357",
    "CVE-2021-2367",
    "CVE-2021-2370",
    "CVE-2021-2372",
    "CVE-2021-2374",
    "CVE-2021-2383",
    "CVE-2021-2384",
    "CVE-2021-2385",
    "CVE-2021-2387",
    "CVE-2021-2389",
    "CVE-2021-2390",
    "CVE-2021-2399",
    "CVE-2021-2402",
    "CVE-2021-2410",
    "CVE-2021-2412",
    "CVE-2021-2417",
    "CVE-2021-2418",
    "CVE-2021-2422",
    "CVE-2021-2424",
    "CVE-2021-2425",
    "CVE-2021-2426",
    "CVE-2021-2427",
    "CVE-2021-2429",
    "CVE-2021-2437",
    "CVE-2021-2440",
    "CVE-2021-2441",
    "CVE-2021-2444"
  );
  script_xref(name:"IAVA", value:"2020-A-0473-S");
  script_xref(name:"IAVA", value:"2021-A-0038");
  script_xref(name:"IAVA", value:"2021-A-0193");
  script_xref(name:"IAVA", value:"2021-A-0333");
  script_xref(name:"IAVA", value:"2021-A-0487");
  script_xref(name:"CEA-ID", value:"CEA-2021-0004");
  script_xref(name:"CEA-ID", value:"CEA-2021-0025");

  script_name(english:"Oracle Linux 8 : mysql:8.0 (ELSA-2021-3590)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Oracle Linux host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Oracle Linux 8 host has packages installed that are affected by multiple vulnerabilities as referenced in the
ELSA-2021-3590 advisory.

  - Vulnerability in the MySQL Server product of Oracle MySQL (component: Server: FTS). Supported versions
    that are affected are 5.6.49 and prior, 5.7.31 and prior and 8.0.21 and prior. Easily exploitable
    vulnerability allows low privileged attacker with network access via multiple protocols to compromise
    MySQL Server. Successful attacks of this vulnerability can result in unauthorized ability to cause a hang
    or frequently repeatable crash (complete DOS) of MySQL Server. CVSS 3.1 Base Score 6.5 (Availability
    impacts). CVSS Vector: (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H). (CVE-2020-14765)

  - Vulnerability in the MySQL Server product of Oracle MySQL (component: InnoDB). Supported versions that are
    affected are 5.7.31 and prior and 8.0.21 and prior. Easily exploitable vulnerability allows high
    privileged attacker with network access via multiple protocols to compromise MySQL Server. Successful
    attacks of this vulnerability can result in unauthorized ability to cause a hang or frequently repeatable
    crash (complete DOS) of MySQL Server. CVSS 3.1 Base Score 4.9 (Availability impacts). CVSS Vector:
    (CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:N/I:N/A:H). (CVE-2020-14776)

  - Vulnerability in the MySQL Server product of Oracle MySQL (component: Server: Locking). Supported versions
    that are affected are 5.6.49 and prior, 5.7.31 and prior and 8.0.21 and prior. Easily exploitable
    vulnerability allows high privileged attacker with network access via multiple protocols to compromise
    MySQL Server. Successful attacks of this vulnerability can result in unauthorized ability to cause a hang
    or frequently repeatable crash (complete DOS) of MySQL Server. CVSS 3.1 Base Score 4.9 (Availability
    impacts). CVSS Vector: (CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:N/I:N/A:H). (CVE-2020-14812)

  - Vulnerability in the MySQL Server product of Oracle MySQL (component: Server: FTS). Supported versions
    that are affected are 5.7.31 and prior and 8.0.21 and prior. Easily exploitable vulnerability allows high
    privileged attacker with network access via multiple protocols to compromise MySQL Server. Successful
    attacks of this vulnerability can result in unauthorized ability to cause a hang or frequently repeatable
    crash (complete DOS) of MySQL Server. CVSS 3.1 Base Score 4.9 (Availability impacts). CVSS Vector:
    (CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:N/I:N/A:H). (CVE-2020-14789)

  - Vulnerability in the MySQL Server product of Oracle MySQL (component: Server: Optimizer). Supported
    versions that are affected are 8.0.21 and prior. Easily exploitable vulnerability allows high privileged
    attacker with network access via multiple protocols to compromise MySQL Server. Successful attacks of this
    vulnerability can result in unauthorized ability to cause a hang or frequently repeatable crash (complete
    DOS) of MySQL Server. CVSS 3.1 Base Score 4.9 (Availability impacts). CVSS Vector:
    (CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:N/I:N/A:H). (CVE-2020-14773, CVE-2020-14777, CVE-2020-14785,
    CVE-2020-14794, CVE-2020-14809, CVE-2020-14837, CVE-2020-14839, CVE-2020-14845, CVE-2020-14861,
    CVE-2020-14866, CVE-2020-14868, CVE-2020-14888, CVE-2020-14891, CVE-2020-14893, CVE-2021-2030,
    CVE-2021-2055, CVE-2021-2412)

  - Vulnerability in the MySQL Server product of Oracle MySQL (component: Server: PS). Supported versions that
    are affected are 8.0.21 and prior. Easily exploitable vulnerability allows high privileged attacker with
    network access via multiple protocols to compromise MySQL Server. Successful attacks of this vulnerability
    can result in unauthorized ability to cause a hang or frequently repeatable crash (complete DOS) of MySQL
    Server. CVSS 3.1 Base Score 4.9 (Availability impacts). CVSS Vector:
    (CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:N/I:N/A:H). (CVE-2020-14786, CVE-2020-14844)

  - Vulnerability in the MySQL Server product of Oracle MySQL (component: Server: PS). Supported versions that
    are affected are 5.7.31 and prior and 8.0.21 and prior. Easily exploitable vulnerability allows high
    privileged attacker with network access via multiple protocols to compromise MySQL Server. Successful
    attacks of this vulnerability can result in unauthorized ability to cause a hang or frequently repeatable
    crash (complete DOS) of MySQL Server. CVSS 3.1 Base Score 4.9 (Availability impacts). CVSS Vector:
    (CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:N/I:N/A:H). (CVE-2020-14790)

  - Vulnerability in the MySQL Server product of Oracle MySQL (component: InnoDB). Supported versions that are
    affected are 8.0.21 and prior. Difficult to exploit vulnerability allows high privileged attacker with
    network access via multiple protocols to compromise MySQL Server. Successful attacks of this vulnerability
    can result in unauthorized ability to cause a partial denial of service (partial DOS) of MySQL Server.
    CVSS 3.1 Base Score 2.2 (Availability impacts). CVSS Vector:
    (CVSS:3.1/AV:N/AC:H/PR:H/UI:N/S:U/C:N/I:N/A:L). (CVE-2020-14791)

  - Vulnerability in the MySQL Server product of Oracle MySQL (component: Server: Optimizer). Supported
    versions that are affected are 5.6.49 and prior, 5.7.31 and prior and 8.0.21 and prior. Easily exploitable
    vulnerability allows high privileged attacker with network access via multiple protocols to compromise
    MySQL Server. Successful attacks of this vulnerability can result in unauthorized ability to cause a hang
    or frequently repeatable crash (complete DOS) of MySQL Server. CVSS 3.1 Base Score 4.9 (Availability
    impacts). CVSS Vector: (CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:N/I:N/A:H). (CVE-2020-14793)

  - Vulnerability in the MySQL Server product of Oracle MySQL (component: Server: Security: Encryption).
    Supported versions that are affected are 8.0.21 and prior. Easily exploitable vulnerability allows low
    privileged attacker with network access via multiple protocols to compromise MySQL Server. Successful
    attacks of this vulnerability can result in unauthorized ability to cause a hang or frequently repeatable
    crash (complete DOS) of MySQL Server. CVSS 3.1 Base Score 6.5 (Availability impacts). CVSS Vector:
    (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H). (CVE-2020-14800)

  - Vulnerability in the MySQL Server product of Oracle MySQL (component: Server: FTS). Supported versions
    that are affected are 8.0.21 and prior. Easily exploitable vulnerability allows high privileged attacker
    with network access via multiple protocols to compromise MySQL Server. Successful attacks of this
    vulnerability can result in unauthorized ability to cause a hang or frequently repeatable crash (complete
    DOS) of MySQL Server. CVSS 3.1 Base Score 4.9 (Availability impacts). CVSS Vector:
    (CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:N/I:N/A:H). (CVE-2020-14804)

  - Vulnerability in the MySQL Server product of Oracle MySQL (component: Server: DML). Supported versions
    that are affected are 8.0.21 and prior. Easily exploitable vulnerability allows high privileged attacker
    with network access via multiple protocols to compromise MySQL Server. Successful attacks of this
    vulnerability can result in unauthorized ability to cause a hang or frequently repeatable crash (complete
    DOS) of MySQL Server. CVSS 3.1 Base Score 4.9 (Availability impacts). CVSS Vector:
    (CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:N/I:N/A:H). (CVE-2020-14814)

  - Vulnerability in the MySQL Server product of Oracle MySQL (component: InnoDB). Supported versions that are
    affected are 8.0.21 and prior. Easily exploitable vulnerability allows high privileged attacker with
    network access via multiple protocols to compromise MySQL Server. Successful attacks of this vulnerability
    can result in unauthorized ability to cause a hang or frequently repeatable crash (complete DOS) of MySQL
    Server. CVSS 3.1 Base Score 4.9 (Availability impacts). CVSS Vector:
    (CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:N/I:N/A:H). (CVE-2020-14821, CVE-2020-14829, CVE-2020-14848,
    CVE-2021-2028)

  - Vulnerability in the MySQL Server product of Oracle MySQL (component: Server: DML). Supported versions
    that are affected are 8.0.21 and prior. Easily exploitable vulnerability allows high privileged attacker
    with network access via multiple protocols to compromise MySQL Server. Successful attacks of this
    vulnerability can result in takeover of MySQL Server. CVSS 3.1 Base Score 7.2 (Confidentiality, Integrity
    and Availability impacts). CVSS Vector: (CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H). (CVE-2020-14828)

  - Vulnerability in the MySQL Server product of Oracle MySQL (component: Server: Stored Procedure). Supported
    versions that are affected are 5.6.49 and prior, 5.7.31 and prior and 8.0.21 and prior. Easily exploitable
    vulnerability allows high privileged attacker with network access via multiple protocols to compromise
    MySQL Server. Successful attacks of this vulnerability can result in unauthorized ability to cause a hang
    or frequently repeatable crash (complete DOS) of MySQL Server. CVSS 3.1 Base Score 4.9 (Availability
    impacts). CVSS Vector: (CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:N/I:N/A:H). (CVE-2020-14672)

  - Vulnerability in the MySQL Server product of Oracle MySQL (component: Server: Optimizer). Supported
    versions that are affected are 5.6.49 and prior, 5.7.31 and prior and 8.0.21 and prior. Easily exploitable
    vulnerability allows low privileged attacker with network access via multiple protocols to compromise
    MySQL Server. Successful attacks of this vulnerability can result in unauthorized ability to cause a hang
    or frequently repeatable crash (complete DOS) of MySQL Server. CVSS 3.1 Base Score 6.5 (Availability
    impacts). CVSS Vector: (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H). (CVE-2020-14769)

  - Vulnerability in the MySQL Server product of Oracle MySQL (component: InnoDB). Supported versions that are
    affected are 5.7.31 and prior and 8.0.21 and prior. Easily exploitable vulnerability allows low privileged
    attacker with network access via multiple protocols to compromise MySQL Server. Successful attacks of this
    vulnerability can result in unauthorized ability to cause a hang or frequently repeatable crash (complete
    DOS) of MySQL Server. CVSS 3.1 Base Score 6.5 (Availability impacts). CVSS Vector:
    (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H). (CVE-2020-14775)

  - Vulnerability in the MySQL Server product of Oracle MySQL (component: Server: Optimizer). Supported
    versions that are affected are 8.0.21 and prior. Easily exploitable vulnerability allows low privileged
    attacker with network access via multiple protocols to compromise MySQL Server. Successful attacks of this
    vulnerability can result in unauthorized ability to cause a hang or frequently repeatable crash (complete
    DOS) of MySQL Server. CVSS 3.1 Base Score 6.5 (Availability impacts). CVSS Vector:
    (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H). (CVE-2020-14830, CVE-2020-14836, CVE-2020-14846)

  - Vulnerability in the MySQL Server product of Oracle MySQL (component: Server: DDL). Supported versions
    that are affected are 5.6.49 and prior, 5.7.31 and prior and 8.0.21 and prior. Difficult to exploit
    vulnerability allows high privileged attacker with network access via multiple protocols to compromise
    MySQL Server. Successful attacks of this vulnerability can result in unauthorized ability to cause a hang
    or frequently repeatable crash (complete DOS) of MySQL Server. CVSS 3.1 Base Score 4.4 (Availability
    impacts). CVSS Vector: (CVSS:3.1/AV:N/AC:H/PR:H/UI:N/S:U/C:N/I:N/A:H). (CVE-2020-14867)

  - Vulnerability in the MySQL Client product of Oracle MySQL (component: C API). Supported versions that are
    affected are 5.6.50 and prior, 5.7.32 and prior and 8.0.22 and prior. Difficult to exploit vulnerability
    allows low privileged attacker with network access via multiple protocols to compromise MySQL Client.
    Successful attacks of this vulnerability can result in unauthorized update, insert or delete access to
    some of MySQL Client accessible data and unauthorized ability to cause a partial denial of service
    (partial DOS) of MySQL Client. CVSS 3.1 Base Score 4.2 (Integrity and Availability impacts). CVSS Vector:
    (CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:N/I:L/A:L). (CVE-2021-2010)

  - Vulnerability in the MySQL Client product of Oracle MySQL (component: C API). Supported versions that are
    affected are 5.7.32 and prior and 8.0.22 and prior. Difficult to exploit vulnerability allows
    unauthenticated attacker with network access via multiple protocols to compromise MySQL Client. Successful
    attacks of this vulnerability can result in unauthorized ability to cause a hang or frequently repeatable
    crash (complete DOS) of MySQL Client. CVSS 3.1 Base Score 5.9 (Availability impacts). CVSS Vector:
    (CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H). (CVE-2021-2011)

  - Vulnerability in the MySQL Server product of Oracle MySQL (component: Server: Optimizer). Supported
    versions that are affected are 8.0.22 and prior. Easily exploitable vulnerability allows high privileged
    attacker with network access via multiple protocols to compromise MySQL Server. Successful attacks of this
    vulnerability can result in unauthorized ability to cause a hang or frequently repeatable crash (complete
    DOS) of MySQL Server. CVSS 3.1 Base Score 4.9 (Availability impacts). CVSS Vector:
    (CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:N/I:N/A:H). (CVE-2021-2021, CVE-2021-2031, CVE-2021-2036,
    CVE-2021-2065, CVE-2021-2070, CVE-2021-2076, CVE-2021-2213)

  - Vulnerability in the MySQL Server product of Oracle MySQL (component: InnoDB). Supported versions that are
    affected are 5.6.50 and prior, 5.7.32 and prior and 8.0.22 and prior. Difficult to exploit vulnerability
    allows high privileged attacker with network access via multiple protocols to compromise MySQL Server.
    Successful attacks of this vulnerability can result in unauthorized ability to cause a hang or frequently
    repeatable crash (complete DOS) of MySQL Server. CVSS 3.1 Base Score 4.4 (Availability impacts). CVSS
    Vector: (CVSS:3.1/AV:N/AC:H/PR:H/UI:N/S:U/C:N/I:N/A:H). (CVE-2021-2022)

  - Vulnerability in the MySQL Server product of Oracle MySQL (component: Server: Optimizer). Supported
    versions that are affected are 8.0.22 and prior. Easily exploitable vulnerability allows low privileged
    attacker with network access via multiple protocols to compromise MySQL Server. Successful attacks of this
    vulnerability can result in unauthorized ability to cause a hang or frequently repeatable crash (complete
    DOS) of MySQL Server. CVSS 3.1 Base Score 6.5 (Availability impacts). CVSS Vector:
    (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H). (CVE-2021-2024)

  - Vulnerability in the MySQL Server product of Oracle MySQL (component: Information Schema). Supported
    versions that are affected are 5.7.32 and prior and 8.0.22 and prior. Easily exploitable vulnerability
    allows low privileged attacker with network access via multiple protocols to compromise MySQL Server.
    Successful attacks of this vulnerability can result in unauthorized read access to a subset of MySQL
    Server accessible data. CVSS 3.1 Base Score 4.3 (Confidentiality impacts). CVSS Vector:
    (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N). (CVE-2021-2032)

  - Vulnerability in the MySQL Server product of Oracle MySQL (component: Server: Stored Procedure). Supported
    versions that are affected are 8.0.22 and prior. Easily exploitable vulnerability allows high privileged
    attacker with network access via multiple protocols to compromise MySQL Server. While the vulnerability is
    in MySQL Server, attacks may significantly impact additional products. Successful attacks of this
    vulnerability can result in unauthorized ability to cause a hang or frequently repeatable crash (complete
    DOS) of MySQL Server. CVSS 3.1 Base Score 6.8 (Availability impacts). CVSS Vector:
    (CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:C/C:N/I:N/A:H). (CVE-2021-2046)

  - Vulnerability in the MySQL Server product of Oracle MySQL (component: Server: Security: Privileges).
    Supported versions that are affected are 8.0.21 and prior. Easily exploitable vulnerability allows low
    privileged attacker with network access via multiple protocols to compromise MySQL Server. Successful
    attacks of this vulnerability can result in unauthorized read access to a subset of MySQL Server
    accessible data. CVSS 3.1 Base Score 4.3 (Confidentiality impacts). CVSS Vector:
    (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N). (CVE-2020-14838)

  - Vulnerability in the MySQL Server product of Oracle MySQL (component: Server: Charsets). Supported
    versions that are affected are 8.0.21 and prior. Easily exploitable vulnerability allows high privileged
    attacker with network access via multiple protocols to compromise MySQL Server. Successful attacks of this
    vulnerability can result in unauthorized ability to cause a hang or frequently repeatable crash (complete
    DOS) of MySQL Server. CVSS 3.1 Base Score 4.9 (Availability impacts). CVSS Vector:
    (CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:N/I:N/A:H). (CVE-2020-14852)

  - Vulnerability in the MySQL Server product of Oracle MySQL (component: Server: Security: Roles). Supported
    versions that are affected are 8.0.21 and prior. Easily exploitable vulnerability allows high privileged
    attacker with network access via multiple protocols to compromise MySQL Server. Successful attacks of this
    vulnerability can result in unauthorized update, insert or delete access to some of MySQL Server
    accessible data. CVSS 3.1 Base Score 2.7 (Integrity impacts). CVSS Vector:
    (CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:N/I:L/A:N). (CVE-2020-14860)

  - Vulnerability in the MySQL Server product of Oracle MySQL (component: Server: X Plugin). Supported
    versions that are affected are 8.0.21 and prior. Easily exploitable vulnerability allows high privileged
    attacker with network access via multiple protocols to compromise MySQL Server. Successful attacks of this
    vulnerability can result in unauthorized ability to cause a hang or frequently repeatable crash (complete
    DOS) of MySQL Server. CVSS 3.1 Base Score 4.9 (Availability impacts). CVSS Vector:
    (CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:N/I:N/A:H). (CVE-2020-14870)

  - Vulnerability in the MySQL Server product of Oracle MySQL (component: Server: Logging). Supported versions
    that are affected are 8.0.21 and prior. Difficult to exploit vulnerability allows high privileged attacker
    with network access via multiple protocols to compromise MySQL Server. Successful attacks of this
    vulnerability can result in unauthorized ability to cause a hang or frequently repeatable crash (complete
    DOS) of MySQL Server. CVSS 3.1 Base Score 4.4 (Availability impacts). CVSS Vector:
    (CVSS:3.1/AV:N/AC:H/PR:H/UI:N/S:U/C:N/I:N/A:H). (CVE-2020-14873)

  - Vulnerability in the MySQL Server product of Oracle MySQL (component: Server: Optimizer). Supported
    versions that are affected are 5.6.50 and prior, 5.7.30 and prior and 8.0.17 and prior. Easily exploitable
    vulnerability allows high privileged attacker with network access via multiple protocols to compromise
    MySQL Server. Successful attacks of this vulnerability can result in unauthorized ability to cause a hang
    or frequently repeatable crash (complete DOS) of MySQL Server. CVSS 3.1 Base Score 4.9 (Availability
    impacts). CVSS Vector: (CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:N/I:N/A:H). (CVE-2021-2001)

  - Vulnerability in the MySQL Server product of Oracle MySQL (component: Server: Replication). Supported
    versions that are affected are 8.0.22 and prior. Easily exploitable vulnerability allows high privileged
    attacker with network access via multiple protocols to compromise MySQL Server. Successful attacks of this
    vulnerability can result in unauthorized ability to cause a hang or frequently repeatable crash (complete
    DOS) of MySQL Server. CVSS 3.1 Base Score 4.9 (Availability impacts). CVSS Vector:
    (CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:N/I:N/A:H). (CVE-2021-2002)

  - Vulnerability in the MySQL Server product of Oracle MySQL (component: Server: Components Services).
    Supported versions that are affected are 8.0.22 and prior. Difficult to exploit vulnerability allows high
    privileged attacker with network access via multiple protocols to compromise MySQL Server. Successful
    attacks of this vulnerability can result in unauthorized ability to cause a hang or frequently repeatable
    crash (complete DOS) of MySQL Server. CVSS 3.1 Base Score 4.4 (Availability impacts). CVSS Vector:
    (CVSS:3.1/AV:N/AC:H/PR:H/UI:N/S:U/C:N/I:N/A:H). (CVE-2021-2038)

  - Vulnerability in the MySQL Server product of Oracle MySQL (component: InnoDB). Supported versions that are
    affected are 8.0.21 and prior. Easily exploitable vulnerability allows high privileged attacker with logon
    to the infrastructure where MySQL Server executes to compromise MySQL Server. Successful attacks of this
    vulnerability can result in unauthorized read access to a subset of MySQL Server accessible data. CVSS 3.1
    Base Score 2.3 (Confidentiality impacts). CVSS Vector: (CVSS:3.1/AV:L/AC:L/PR:H/UI:N/S:U/C:L/I:N/A:N).
    (CVE-2021-2042)

  - Vulnerability in the MySQL Server product of Oracle MySQL (component: InnoDB). Supported versions that are
    affected are 8.0.22 and prior. Difficult to exploit vulnerability allows high privileged attacker with
    network access via multiple protocols to compromise MySQL Server. Successful attacks of this vulnerability
    can result in unauthorized ability to cause a hang or frequently repeatable crash (complete DOS) of MySQL
    Server as well as unauthorized update, insert or delete access to some of MySQL Server accessible data.
    CVSS 3.1 Base Score 5.0 (Integrity and Availability impacts). CVSS Vector:
    (CVSS:3.1/AV:N/AC:H/PR:H/UI:N/S:U/C:N/I:L/A:H). (CVE-2021-2048)

  - Vulnerability in the MySQL Server product of Oracle MySQL (component: Server: DML). Supported versions
    that are affected are 8.0.22 and prior. Difficult to exploit vulnerability allows high privileged attacker
    with network access via multiple protocols to compromise MySQL Server. Successful attacks of this
    vulnerability can result in unauthorized ability to cause a hang or frequently repeatable crash (complete
    DOS) of MySQL Server. CVSS 3.1 Base Score 4.4 (Availability impacts). CVSS Vector:
    (CVSS:3.1/AV:N/AC:H/PR:H/UI:N/S:U/C:N/I:N/A:H). (CVE-2021-2056)

  - Vulnerability in the MySQL Server product of Oracle MySQL (component: Server: Locking). Supported versions
    that are affected are 8.0.22 and prior. Easily exploitable vulnerability allows high privileged attacker
    with network access via multiple protocols to compromise MySQL Server. Successful attacks of this
    vulnerability can result in unauthorized ability to cause a hang or frequently repeatable crash (complete
    DOS) of MySQL Server. CVSS 3.1 Base Score 4.9 (Availability impacts). CVSS Vector:
    (CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:N/I:N/A:H). (CVE-2021-2058)

  - Vulnerability in the MySQL Server product of Oracle MySQL (component: Server: Optimizer). Supported
    versions that are affected are 5.6.50 and prior, 5.7.32 and prior and 8.0.22 and prior. Easily exploitable
    vulnerability allows high privileged attacker with network access via multiple protocols to compromise
    MySQL Server. Successful attacks of this vulnerability can result in unauthorized ability to cause a hang
    or frequently repeatable crash (complete DOS) of MySQL Server. CVSS 3.1 Base Score 4.9 (Availability
    impacts). CVSS Vector: (CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:N/I:N/A:H). (CVE-2021-2060)

  - Vulnerability in the MySQL Server product of Oracle MySQL (component: Server: DDL). Supported versions
    that are affected are 8.0.22 and prior. Difficult to exploit vulnerability allows high privileged attacker
    with network access via multiple protocols to compromise MySQL Server. Successful attacks of this
    vulnerability can result in unauthorized ability to cause a hang or frequently repeatable crash (complete
    DOS) of MySQL Server. CVSS 3.1 Base Score 4.4 (Availability impacts). CVSS Vector:
    (CVSS:3.1/AV:N/AC:H/PR:H/UI:N/S:U/C:N/I:N/A:H). (CVE-2021-2061)

  - Vulnerability in the MySQL Server product of Oracle MySQL (component: Server: Stored Procedure). Supported
    versions that are affected are 8.0.22 and prior. Easily exploitable vulnerability allows high privileged
    attacker with network access via multiple protocols to compromise MySQL Server. Successful attacks of this
    vulnerability can result in unauthorized ability to cause a hang or frequently repeatable crash (complete
    DOS) of MySQL Server. CVSS 3.1 Base Score 4.9 (Availability impacts). CVSS Vector:
    (CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:N/I:N/A:H). (CVE-2021-2072, CVE-2021-2081)

  - Vulnerability in the MySQL Server product of Oracle MySQL (component: Server: DML). Supported versions
    that are affected are 8.0.22 and prior. Easily exploitable vulnerability allows high privileged attacker
    with logon to the infrastructure where MySQL Server executes to compromise MySQL Server. Successful
    attacks of this vulnerability can result in unauthorized ability to cause a hang or frequently repeatable
    crash (complete DOS) of MySQL Server. CVSS 3.1 Base Score 4.4 (Availability impacts). CVSS Vector:
    (CVSS:3.1/AV:L/AC:L/PR:H/UI:N/S:U/C:N/I:N/A:H). (CVE-2021-2087, CVE-2021-2088)

  - Vulnerability in the MySQL Server product of Oracle MySQL (component: Server: DDL). Supported versions
    that are affected are 8.0.22 and prior. Easily exploitable vulnerability allows high privileged attacker
    with network access via multiple protocols to compromise MySQL Server. Successful attacks of this
    vulnerability can result in unauthorized ability to cause a hang or frequently repeatable crash (complete
    DOS) of MySQL Server. CVSS 3.1 Base Score 4.9 (Availability impacts). CVSS Vector:
    (CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:N/I:N/A:H). (CVE-2021-2122)

  - Vulnerability in the MySQL Server product of Oracle MySQL (component: Server: DML). Supported versions
    that are affected are 5.7.33 and prior and 8.0.23 and prior. Easily exploitable vulnerability allows high
    privileged attacker with network access via multiple protocols to compromise MySQL Server. Successful
    attacks of this vulnerability can result in unauthorized ability to cause a hang or frequently repeatable
    crash (complete DOS) of MySQL Server. CVSS 3.1 Base Score 4.9 (Availability impacts). CVSS Vector:
    (CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:N/I:N/A:H). (CVE-2021-2166)

  - Vulnerability in the MySQL Server product of Oracle MySQL (component: Server: Optimizer). Supported
    versions that are affected are 5.7.33 and prior and 8.0.23 and prior. Easily exploitable vulnerability
    allows high privileged attacker with network access via multiple protocols to compromise MySQL Server.
    Successful attacks of this vulnerability can result in unauthorized ability to cause a hang or frequently
    repeatable crash (complete DOS) of MySQL Server. CVSS 3.1 Base Score 4.9 (Availability impacts). CVSS
    Vector: (CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:N/I:N/A:H). (CVE-2021-2169)

  - Vulnerability in the MySQL Server product of Oracle MySQL (component: Server: Optimizer). Supported
    versions that are affected are 8.0.23 and prior. Easily exploitable vulnerability allows high privileged
    attacker with network access via multiple protocols to compromise MySQL Server. Successful attacks of this
    vulnerability can result in unauthorized ability to cause a hang or frequently repeatable crash (complete
    DOS) of MySQL Server. CVSS 3.1 Base Score 4.9 (Availability impacts). CVSS Vector:
    (CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:N/I:N/A:H). (CVE-2021-2164, CVE-2021-2170, CVE-2021-2193,
    CVE-2021-2203, CVE-2021-2212, CVE-2021-2230, CVE-2021-2278, CVE-2021-2299, CVE-2021-2444)

  - Vulnerability in the MySQL Server product of Oracle MySQL (component: Server: DML). Supported versions
    that are affected are 8.0.23 and prior. Easily exploitable vulnerability allows low privileged attacker
    with network access via multiple protocols to compromise MySQL Server. Successful attacks of this
    vulnerability can result in unauthorized ability to cause a hang or frequently repeatable crash (complete
    DOS) of MySQL Server. CVSS 3.1 Base Score 6.5 (Availability impacts). CVSS Vector:
    (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H). (CVE-2021-2172)

  - Vulnerability in the MySQL Server product of Oracle MySQL (component: InnoDB). Supported versions that are
    affected are 5.7.33 and prior and 8.0.23 and prior. Difficult to exploit vulnerability allows high
    privileged attacker with network access via multiple protocols to compromise MySQL Server. Successful
    attacks of this vulnerability can result in unauthorized ability to cause a hang or frequently repeatable
    crash (complete DOS) of MySQL Server. CVSS 3.1 Base Score 4.4 (Availability impacts). CVSS Vector:
    (CVSS:3.1/AV:N/AC:H/PR:H/UI:N/S:U/C:N/I:N/A:H). (CVE-2021-2174)

  - Vulnerability in the MySQL Server product of Oracle MySQL (component: Server: Group Replication Plugin).
    Supported versions that are affected are 5.7.33 and prior and 8.0.23 and prior. Easily exploitable
    vulnerability allows high privileged attacker with network access via multiple protocols to compromise
    MySQL Server. Successful attacks of this vulnerability can result in unauthorized ability to cause a hang
    or frequently repeatable crash (complete DOS) of MySQL Server. CVSS 3.1 Base Score 4.9 (Availability
    impacts). CVSS Vector: (CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:N/I:N/A:H). (CVE-2021-2179)

  - Vulnerability in the MySQL Server product of Oracle MySQL (component: InnoDB). Supported versions that are
    affected are 5.7.33 and prior and 8.0.23 and prior. Easily exploitable vulnerability allows high
    privileged attacker with network access via multiple protocols to compromise MySQL Server. Successful
    attacks of this vulnerability can result in unauthorized ability to cause a hang or frequently repeatable
    crash (complete DOS) of MySQL Server. CVSS 3.1 Base Score 4.9 (Availability impacts). CVSS Vector:
    (CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:N/I:N/A:H). (CVE-2021-2180, CVE-2021-2194)

  - Vulnerability in the MySQL Server product of Oracle MySQL (component: Server: Options). Supported versions
    that are affected are 5.7.33 and prior and 8.0.23 and prior. Easily exploitable vulnerability allows high
    privileged attacker with network access via multiple protocols to compromise MySQL Server. Successful
    attacks of this vulnerability can result in unauthorized ability to cause a hang or frequently repeatable
    crash (complete DOS) of MySQL Server. CVSS 3.1 Base Score 4.9 (Availability impacts). CVSS Vector:
    (CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:N/I:N/A:H). (CVE-2021-2146)

  - Vulnerability in the MySQL Server product of Oracle MySQL (component: Server: Replication). Supported
    versions that are affected are 5.7.33 and prior and 8.0.23 and prior. Difficult to exploit vulnerability
    allows high privileged attacker with network access via multiple protocols to compromise MySQL Server.
    Successful attacks of this vulnerability can result in unauthorized ability to cause a hang or frequently
    repeatable crash (complete DOS) of MySQL Server. CVSS 3.1 Base Score 4.4 (Availability impacts). CVSS
    Vector: (CVSS:3.1/AV:N/AC:H/PR:H/UI:N/S:U/C:N/I:N/A:H). (CVE-2021-2171)

  - Vulnerability in the MySQL Server product of Oracle MySQL (component: Server: Replication). Supported
    versions that are affected are 5.7.32 and prior and 8.0.22 and prior. Easily exploitable vulnerability
    allows low privileged attacker with network access via multiple protocols to compromise MySQL Server.
    Successful attacks of this vulnerability can result in unauthorized ability to cause a hang or frequently
    repeatable crash (complete DOS) of MySQL Server. CVSS 3.1 Base Score 6.5 (Availability impacts). CVSS
    Vector: (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H). (CVE-2021-2178, CVE-2021-2202)

  - Vulnerability in the MySQL Server product of Oracle MySQL (component: Server: DML). Supported versions
    that are affected are 8.0.23 and prior. Easily exploitable vulnerability allows high privileged attacker
    with network access via multiple protocols to compromise MySQL Server. Successful attacks of this
    vulnerability can result in unauthorized ability to cause a hang or frequently repeatable crash (complete
    DOS) of MySQL Server. CVSS 3.1 Base Score 4.9 (Availability impacts). CVSS Vector:
    (CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:N/I:N/A:H). (CVE-2021-2196, CVE-2021-2300, CVE-2021-2305)

  - Vulnerability in the MySQL Server product of Oracle MySQL (component: Server: Stored Procedure). Supported
    versions that are affected are 8.0.23 and prior. Easily exploitable vulnerability allows high privileged
    attacker with network access via multiple protocols to compromise MySQL Server. Successful attacks of this
    vulnerability can result in unauthorized ability to cause a hang or frequently repeatable crash (complete
    DOS) of MySQL Server. CVSS 3.1 Base Score 4.9 (Availability impacts). CVSS Vector:
    (CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:N/I:N/A:H). (CVE-2021-2215, CVE-2021-2217, CVE-2021-2293)

  - Vulnerability in the MySQL Server product of Oracle MySQL (component: Server: DDL). Supported versions
    that are affected are 8.0.25 and prior. Easily exploitable vulnerability allows high privileged attacker
    with network access via multiple protocols to compromise MySQL Server. Successful attacks of this
    vulnerability can result in unauthorized ability to cause a hang or frequently repeatable crash (complete
    DOS) of MySQL Server. CVSS 3.1 Base Score 4.9 (Availability impacts). CVSS Vector:
    (CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:N/I:N/A:H). (CVE-2021-2339, CVE-2021-2352, CVE-2021-2399)

  - Vulnerability in the MySQL Server product of Oracle MySQL (component: Server: Optimizer). Supported
    versions that are affected are 5.7.34 and prior and 8.0.25 and prior. Easily exploitable vulnerability
    allows high privileged attacker with network access via multiple protocols to compromise MySQL Server.
    Successful attacks of this vulnerability can result in unauthorized ability to cause a hang or frequently
    repeatable crash (complete DOS) of MySQL Server. CVSS 3.1 Base Score 4.9 (Availability impacts). CVSS
    Vector: (CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:N/I:N/A:H). (CVE-2021-2342)

  - Vulnerability in the MySQL Server product of Oracle MySQL (component: Server: Federated). Supported
    versions that are affected are 8.0.25 and prior. Easily exploitable vulnerability allows high privileged
    attacker with network access via multiple protocols to compromise MySQL Server. Successful attacks of this
    vulnerability can result in unauthorized ability to cause a hang or frequently repeatable crash (complete
    DOS) of MySQL Server. CVSS 3.1 Base Score 4.9 (Availability impacts). CVSS Vector:
    (CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:N/I:N/A:H). (CVE-2021-2354)

  - Vulnerability in the MySQL Server product of Oracle MySQL (component: InnoDB). Supported versions that are
    affected are 5.7.34 and prior and 8.0.25 and prior. Difficult to exploit vulnerability allows high
    privileged attacker with network access via multiple protocols to compromise MySQL Server. Successful
    attacks of this vulnerability can result in unauthorized ability to cause a hang or frequently repeatable
    crash (complete DOS) of MySQL Server. CVSS 3.1 Base Score 4.4 (Availability impacts). CVSS Vector:
    (CVSS:3.1/AV:N/AC:H/PR:H/UI:N/S:U/C:N/I:N/A:H). (CVE-2021-2372)

  - Vulnerability in the MySQL Server product of Oracle MySQL (component: Server: Optimizer). Supported
    versions that are affected are 8.0.25 and prior. Easily exploitable vulnerability allows high privileged
    attacker with network access via multiple protocols to compromise MySQL Server. Successful attacks of this
    vulnerability can result in unauthorized ability to cause a hang or frequently repeatable crash (complete
    DOS) of MySQL Server. CVSS 3.1 Base Score 4.9 (Availability impacts). CVSS Vector:
    (CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:N/I:N/A:H). (CVE-2021-2357, CVE-2021-2367, CVE-2021-2383,
    CVE-2021-2384, CVE-2021-2387, CVE-2021-2410, CVE-2021-2418, CVE-2021-2425, CVE-2021-2426, CVE-2021-2427,
    CVE-2021-2437, CVE-2021-2441)

  - Vulnerability in the MySQL Server product of Oracle MySQL (component: Server: Partition). Supported
    versions that are affected are 8.0.23 and prior. Easily exploitable vulnerability allows high privileged
    attacker with network access via multiple protocols to compromise MySQL Server. Successful attacks of this
    vulnerability can result in unauthorized ability to cause a hang or frequently repeatable crash (complete
    DOS) of MySQL Server. CVSS 3.1 Base Score 4.9 (Availability impacts). CVSS Vector:
    (CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:N/I:N/A:H). (CVE-2021-2201, CVE-2021-2208)

  - Vulnerability in the MySQL Server product of Oracle MySQL (component: Server: Information Schema).
    Supported versions that are affected are 5.7.33 and prior and 8.0.23 and prior. Easily exploitable
    vulnerability allows high privileged attacker with network access via multiple protocols to compromise
    MySQL Server. Successful attacks of this vulnerability can result in unauthorized access to critical data
    or complete access to all MySQL Server accessible data. CVSS 3.1 Base Score 4.9 (Confidentiality impacts).
    CVSS Vector: (CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:N/A:N). (CVE-2021-2226)

  - Vulnerability in the MySQL Server product of Oracle MySQL (component: Server: Group Replication Plugin).
    Supported versions that are affected are 8.0.23 and prior. Difficult to exploit vulnerability allows high
    privileged attacker with logon to the infrastructure where MySQL Server executes to compromise MySQL
    Server. Successful attacks of this vulnerability can result in unauthorized ability to cause a partial
    denial of service (partial DOS) of MySQL Server. CVSS 3.1 Base Score 1.9 (Availability impacts). CVSS
    Vector: (CVSS:3.1/AV:L/AC:H/PR:H/UI:N/S:U/C:N/I:N/A:L). (CVE-2021-2232)

  - Vulnerability in the MySQL Server product of Oracle MySQL (component: Server: Optimizer). Supported
    versions that are affected are 8.0.23 and prior. Easily exploitable vulnerability allows low privileged
    attacker with network access via multiple protocols to compromise MySQL Server. Successful attacks of this
    vulnerability can result in unauthorized ability to cause a hang or frequently repeatable crash (complete
    DOS) of MySQL Server. CVSS 3.1 Base Score 6.5 (Availability impacts). CVSS Vector:
    (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H). (CVE-2021-2298)

  - Vulnerability in the MySQL Server product of Oracle MySQL (component: Server: Information Schema).
    Supported versions that are affected are 8.0.23 and prior. Easily exploitable vulnerability allows high
    privileged attacker with network access via multiple protocols to compromise MySQL Server. Successful
    attacks of this vulnerability can result in unauthorized read access to a subset of MySQL Server
    accessible data. CVSS 3.1 Base Score 2.7 (Confidentiality impacts). CVSS Vector:
    (CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:L/I:N/A:N). (CVE-2021-2301, CVE-2021-2308)

  - Vulnerability in the MySQL Server product of Oracle MySQL (component: Server: Stored Procedure). Supported
    versions that are affected are 8.0.23 and prior. Easily exploitable vulnerability allows high privileged
    attacker with network access via multiple protocols to compromise MySQL Server. Successful attacks of this
    vulnerability can result in unauthorized ability to cause a hang or frequently repeatable crash (complete
    DOS) of MySQL Server as well as unauthorized update, insert or delete access to some of MySQL Server
    accessible data. CVSS 3.1 Base Score 5.5 (Integrity and Availability impacts). CVSS Vector:
    (CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:N/I:L/A:H). (CVE-2021-2304)

  - Vulnerability in the MySQL Server product of Oracle MySQL (component: Server: Packaging). Supported
    versions that are affected are 5.7.33 and prior and 8.0.23 and prior. Easily exploitable vulnerability
    allows unauthenticated attacker with logon to the infrastructure where MySQL Server executes to compromise
    MySQL Server. Successful attacks require human interaction from a person other than the attacker.
    Successful attacks of this vulnerability can result in unauthorized access to critical data or complete
    access to all MySQL Server accessible data as well as unauthorized update, insert or delete access to some
    of MySQL Server accessible data. CVSS 3.1 Base Score 6.1 (Confidentiality and Integrity impacts). CVSS
    Vector: (CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:L/A:N). (CVE-2021-2307)

  - Vulnerability in the MySQL Server product of Oracle MySQL (component: Server: Memcached). Supported
    versions that are affected are 8.0.25 and prior. Easily exploitable vulnerability allows high privileged
    attacker with network access via multiple protocols to compromise MySQL Server. Successful attacks of this
    vulnerability can result in unauthorized ability to cause a partial denial of service (partial DOS) of
    MySQL Server. CVSS 3.1 Base Score 2.7 (Availability impacts). CVSS Vector:
    (CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:N/I:N/A:L). (CVE-2021-2340)

  - Vulnerability in the MySQL Server product of Oracle MySQL (component: Server: Replication). Supported
    versions that are affected are 5.7.34 and prior and 8.0.25 and prior. Difficult to exploit vulnerability
    allows low privileged attacker with network access via multiple protocols to compromise MySQL Server.
    Successful attacks of this vulnerability can result in unauthorized ability to cause a hang or frequently
    repeatable crash (complete DOS) of MySQL Server as well as unauthorized update, insert or delete access to
    some of MySQL Server accessible data. CVSS 3.1 Base Score 5.9 (Integrity and Availability impacts). CVSS
    Vector: (CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:N/I:L/A:H). (CVE-2021-2356)

  - Vulnerability in the MySQL Server product of Oracle MySQL (component: Server: DML). Supported versions
    that are affected are 8.0.25 and prior. Easily exploitable vulnerability allows high privileged attacker
    with network access via multiple protocols to compromise MySQL Server. Successful attacks of this
    vulnerability can result in unauthorized ability to cause a hang or frequently repeatable crash (complete
    DOS) of MySQL Server. CVSS 3.1 Base Score 4.9 (Availability impacts). CVSS Vector:
    (CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:N/I:N/A:H). (CVE-2021-2370, CVE-2021-2440)

  - Vulnerability in the MySQL Server product of Oracle MySQL (component: InnoDB). Supported versions that are
    affected are 8.0.25 and prior. Difficult to exploit vulnerability allows high privileged attacker with
    logon to the infrastructure where MySQL Server executes to compromise MySQL Server. Successful attacks of
    this vulnerability can result in unauthorized access to critical data or complete access to all MySQL
    Server accessible data. CVSS 3.1 Base Score 4.1 (Confidentiality impacts). CVSS Vector:
    (CVSS:3.1/AV:L/AC:H/PR:H/UI:N/S:U/C:H/I:N/A:N). (CVE-2021-2374)

  - Vulnerability in the MySQL Server product of Oracle MySQL (component: Server: Replication). Supported
    versions that are affected are 5.7.34 and prior and 8.0.25 and prior. Difficult to exploit vulnerability
    allows high privileged attacker with network access via multiple protocols to compromise MySQL Server.
    Successful attacks of this vulnerability can result in unauthorized ability to cause a hang or frequently
    repeatable crash (complete DOS) of MySQL Server as well as unauthorized update, insert or delete access to
    some of MySQL Server accessible data. CVSS 3.1 Base Score 5.0 (Integrity and Availability impacts). CVSS
    Vector: (CVSS:3.1/AV:N/AC:H/PR:H/UI:N/S:U/C:N/I:L/A:H). (CVE-2021-2385)

  - Vulnerability in the MySQL Server product of Oracle MySQL (component: InnoDB). Supported versions that are
    affected are 5.7.34 and prior and 8.0.25 and prior. Difficult to exploit vulnerability allows
    unauthenticated attacker with network access via multiple protocols to compromise MySQL Server. Successful
    attacks of this vulnerability can result in unauthorized ability to cause a hang or frequently repeatable
    crash (complete DOS) of MySQL Server. CVSS 3.1 Base Score 5.9 (Availability impacts). CVSS Vector:
    (CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H). (CVE-2021-2389, CVE-2021-2390)

  - Vulnerability in the MySQL Server product of Oracle MySQL (component: Server: Locking). Supported versions
    that are affected are 8.0.25 and prior. Easily exploitable vulnerability allows high privileged attacker
    with network access via multiple protocols to compromise MySQL Server. Successful attacks of this
    vulnerability can result in unauthorized ability to cause a hang or frequently repeatable crash (complete
    DOS) of MySQL Server. CVSS 3.1 Base Score 4.9 (Availability impacts). CVSS Vector:
    (CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:N/I:N/A:H). (CVE-2021-2402)

  - Vulnerability in the MySQL Server product of Oracle MySQL (component: Server: GIS). Supported versions
    that are affected are 8.0.25 and prior. Easily exploitable vulnerability allows high privileged attacker
    with network access via multiple protocols to compromise MySQL Server. Successful attacks of this
    vulnerability can result in unauthorized ability to cause a hang or frequently repeatable crash (complete
    DOS) of MySQL Server as well as unauthorized update, insert or delete access to some of MySQL Server
    accessible data and unauthorized read access to a subset of MySQL Server accessible data. CVSS 3.1 Base
    Score 6.0 (Confidentiality, Integrity and Availability impacts). CVSS Vector:
    (CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:L/I:L/A:H). (CVE-2021-2417)

  - Vulnerability in the MySQL Server product of Oracle MySQL (component: Server: Stored Procedure). Supported
    versions that are affected are 8.0.25 and prior. Easily exploitable vulnerability allows high privileged
    attacker with network access via multiple protocols to compromise MySQL Server. Successful attacks of this
    vulnerability can result in unauthorized ability to cause a hang or frequently repeatable crash (complete
    DOS) of MySQL Server. CVSS 3.1 Base Score 4.9 (Availability impacts). CVSS Vector:
    (CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:N/I:N/A:H). (CVE-2021-2424)

  - Vulnerability in the MySQL Server product of Oracle MySQL (component: InnoDB). Supported versions that are
    affected are 8.0.25 and prior. Difficult to exploit vulnerability allows unauthenticated attacker with
    network access via multiple protocols to compromise MySQL Server. Successful attacks of this vulnerability
    can result in unauthorized ability to cause a hang or frequently repeatable crash (complete DOS) of MySQL
    Server. CVSS 3.1 Base Score 5.9 (Availability impacts). CVSS Vector:
    (CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H). (CVE-2021-2429)

  - Vulnerability in the MySQL Server product of Oracle MySQL (component: Server: PS). Supported versions that
    are affected are 8.0.25 and prior. Easily exploitable vulnerability allows high privileged attacker with
    network access via multiple protocols to compromise MySQL Server. Successful attacks of this vulnerability
    can result in unauthorized ability to cause a hang or frequently repeatable crash (complete DOS) of MySQL
    Server. CVSS 3.1 Base Score 4.9 (Availability impacts). CVSS Vector:
    (CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:N/I:N/A:H). (CVE-2021-2422)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://linux.oracle.com/errata/ELSA-2021-3590.html");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-2417");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2020-14828");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/10/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/09/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/09/23");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:mecab");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:mecab-ipadic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:mecab-ipadic-EUCJP");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:mysql-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:mysql-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:mysql-errmsg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:mysql-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:mysql-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:mysql-test");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Oracle Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/OracleLinux", "Host/RedHat/release", "Host/RedHat/rpm-list", "Host/local_checks_enabled");

  exit(0);
}


include('audit.inc');
include('global_settings.inc');
include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item('Host/OracleLinux')) audit(AUDIT_OS_NOT, 'Oracle Linux');
var release = get_kb_item("Host/RedHat/release");
if (isnull(release) || !pregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux)", string:release)) audit(AUDIT_OS_NOT, 'Oracle Linux');
var os_ver = pregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux) .*release ([0-9]+(\.[0-9]+)?)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'Oracle Linux');
var os_ver = os_ver[1];
if (! preg(pattern:"^8([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, 'Oracle Linux 8', 'Oracle Linux ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Oracle Linux', cpu);

var module_ver = get_kb_item('Host/RedHat/appstream/mysql');
if (isnull(module_ver)) audit(AUDIT_PACKAGE_NOT_INSTALLED, 'Module mysql:8.0');
if ('8.0' >!< module_ver) audit(AUDIT_PACKAGE_NOT_AFFECTED, 'Module mysql:' + module_ver);

var appstreams = {
    'mysql:8.0': [
      {'reference':'mecab-0.996-1.module+el8.0.0+5253+1dce7bb2.9', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'mecab-0.996-1.module+el8.0.0+5253+1dce7bb2.9', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'mecab-ipadic-2.7.0.20070801-16.0.1.module+el8.0.0+5253+1dce7bb2', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'mecab-ipadic-2.7.0.20070801-16.0.1.module+el8.0.0+5253+1dce7bb2', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'mecab-ipadic-EUCJP-2.7.0.20070801-16.0.1.module+el8.0.0+5253+1dce7bb2', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'mecab-ipadic-EUCJP-2.7.0.20070801-16.0.1.module+el8.0.0+5253+1dce7bb2', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'mysql-8.0.26-1.module+el8.4.0+20311+30d12931', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'mysql-8.0.26-1.module+el8.4.0+20311+30d12931', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'mysql-common-8.0.26-1.module+el8.4.0+20311+30d12931', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'mysql-common-8.0.26-1.module+el8.4.0+20311+30d12931', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'mysql-devel-8.0.26-1.module+el8.4.0+20311+30d12931', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'mysql-devel-8.0.26-1.module+el8.4.0+20311+30d12931', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'mysql-errmsg-8.0.26-1.module+el8.4.0+20311+30d12931', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'mysql-errmsg-8.0.26-1.module+el8.4.0+20311+30d12931', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'mysql-libs-8.0.26-1.module+el8.4.0+20311+30d12931', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'mysql-libs-8.0.26-1.module+el8.4.0+20311+30d12931', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'mysql-server-8.0.26-1.module+el8.4.0+20311+30d12931', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'mysql-server-8.0.26-1.module+el8.4.0+20311+30d12931', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'mysql-test-8.0.26-1.module+el8.4.0+20311+30d12931', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'mysql-test-8.0.26-1.module+el8.4.0+20311+30d12931', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE}
    ]
};

var flag = 0;
var appstreams_found = 0;
foreach var module (keys(appstreams)) {
  var appstream = NULL;
  var appstream_name = NULL;
  var appstream_version = NULL;
  var appstream_split = split(module, sep:':', keep:FALSE);
  if (!empty_or_null(appstream_split)) {
    appstream_name = appstream_split[0];
    appstream_version = appstream_split[1];
    if (!empty_or_null(appstream_name)) appstream = get_one_kb_item('Host/RedHat/appstream/' + appstream_name);
  }
  if (!empty_or_null(appstream) && appstream_version == appstream || appstream_name == 'all') {
    appstreams_found++;
    foreach var package_array ( appstreams[module] ) {
      var reference = NULL;
      var release = NULL;
      var sp = NULL;
      var cpu = NULL;
      var el_string = NULL;
      var rpm_spec_vers_cmp = NULL;
      var epoch = NULL;
      var allowmaj = NULL;
      if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
      if (!empty_or_null(package_array['release'])) release = 'EL' + package_array['release'];
      if (!empty_or_null(package_array['sp'])) sp = package_array['sp'];
      if (!empty_or_null(package_array['cpu'])) cpu = package_array['cpu'];
      if (!empty_or_null(package_array['el_string'])) el_string = package_array['el_string'];
      if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
      if (!empty_or_null(package_array['epoch'])) epoch = package_array['epoch'];
      if (!empty_or_null(package_array['allowmaj'])) allowmaj = package_array['allowmaj'];
      if (reference && release) {
        if (rpm_check(release:release, sp:sp, cpu:cpu, reference:reference, epoch:epoch, el_string:el_string, rpm_spec_vers_cmp:rpm_spec_vers_cmp, allowmaj:allowmaj)) flag++;
      }
    }
  }
}

if (!appstreams_found) audit(AUDIT_PACKAGE_NOT_INSTALLED, 'Module mysql:8.0');

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'mecab / mecab-ipadic / mecab-ipadic-EUCJP / etc');
}
