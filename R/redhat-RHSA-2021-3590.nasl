#%NASL_MIN_LEVEL 70300
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2021:3590. The text
# itself is copyright (C) Red Hat, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(153522);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/24");

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
    "CVE-2021-2444",
    "CVE-2021-35537",
    "CVE-2021-35629"
  );
  script_xref(name:"IAVA", value:"2021-A-0038");
  script_xref(name:"IAVA", value:"2020-A-0473-S");
  script_xref(name:"IAVA", value:"2021-A-0193");
  script_xref(name:"IAVA", value:"2021-A-0333");
  script_xref(name:"RHSA", value:"2021:3590");
  script_xref(name:"IAVA", value:"2021-A-0487");
  script_xref(name:"CEA-ID", value:"CEA-2021-0004");
  script_xref(name:"CEA-ID", value:"CEA-2021-0025");

  script_name(english:"RHEL 8 : mysql:8.0 (RHSA-2021:3590)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Red Hat host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Redhat Enterprise Linux 8 host has packages installed that are affected by multiple vulnerabilities as
referenced in the RHSA-2021:3590 advisory.

  - mysql: Server: Stored Procedure unspecified vulnerability (CPU Oct 2020) (CVE-2020-14672)

  - mysql: Server: FTS unspecified vulnerability (CPU Oct 2020) (CVE-2020-14765, CVE-2020-14789,
    CVE-2020-14804)

  - mysql: Server: Optimizer unspecified vulnerability (CPU Oct 2020) (CVE-2020-14769, CVE-2020-14773,
    CVE-2020-14777, CVE-2020-14785, CVE-2020-14793, CVE-2020-14794, CVE-2020-14809, CVE-2020-14830,
    CVE-2020-14836, CVE-2020-14837, CVE-2020-14839, CVE-2020-14845, CVE-2020-14846, CVE-2020-14861,
    CVE-2020-14866, CVE-2020-14868, CVE-2020-14888, CVE-2020-14891, CVE-2020-14893)

  - mysql: InnoDB unspecified vulnerability (CPU Oct 2020) (CVE-2020-14775, CVE-2020-14776, CVE-2020-14791,
    CVE-2020-14821, CVE-2020-14829, CVE-2020-14848)

  - mysql: Server: PS unspecified vulnerability (CPU Oct 2020) (CVE-2020-14786, CVE-2020-14790,
    CVE-2020-14844)

  - mysql: Server: Security: Encryption unspecified vulnerability (CPU Oct 2020) (CVE-2020-14800)

  - mysql: Server: Locking unspecified vulnerability (CPU Oct 2020) (CVE-2020-14812)

  - mysql: Server: DML unspecified vulnerability (CPU Oct 2020) (CVE-2020-14814, CVE-2020-14828)

  - mysql: Server: Security: Privileges unspecified vulnerability (CPU Oct 2020) (CVE-2020-14838)

  - mysql: Server: Charsets unspecified vulnerability (CPU Oct 2020) (CVE-2020-14852)

  - mysql: Server: Security: Roles unspecified vulnerability (CPU Oct 2020) (CVE-2020-14860)

  - mysql: Server: DDL unspecified vulnerability (CPU Oct 2020) (CVE-2020-14867)

  - mysql: Server: X Plugin unspecified vulnerability (CPU Oct 2020) (CVE-2020-14870)

  - mysql: Server: Logging unspecified vulnerability (CPU Oct 2020) (CVE-2020-14873)

  - mysql: Server: Optimizer unspecified vulnerability (CPU Jan 2021) (CVE-2021-2001, CVE-2021-2021,
    CVE-2021-2024, CVE-2021-2030, CVE-2021-2031, CVE-2021-2036, CVE-2021-2055, CVE-2021-2060, CVE-2021-2065,
    CVE-2021-2070, CVE-2021-2076)

  - mysql: Server: Replication unspecified vulnerability (CPU Jan 2021) (CVE-2021-2002)

  - mysql: C API unspecified vulnerability (CPU Jan 2021) (CVE-2021-2010, CVE-2021-2011)

  - mysql: InnoDB unspecified vulnerability (CPU Jan 2021) (CVE-2021-2022, CVE-2021-2028, CVE-2021-2042,
    CVE-2021-2048)

  - mysql: Information Schema unspecified vulnerability (CPU Jan 2021) (CVE-2021-2032)

  - mysql: Server: Components Services unspecified vulnerability (CPU Jan 2021) (CVE-2021-2038)

  - mysql: Server: Stored Procedure unspecified vulnerability (CPU Jan 2021) (CVE-2021-2046, CVE-2021-2072,
    CVE-2021-2081)

  - mysql: Server: DML unspecified vulnerability (CPU Jan 2021) (CVE-2021-2056, CVE-2021-2087, CVE-2021-2088)

  - mysql: Server: Locking unspecified vulnerability (CPU Jan 2021) (CVE-2021-2058)

  - mysql: Server: DDL unspecified vulnerability (CPU Jan 2021) (CVE-2021-2061, CVE-2021-2122)

  - mysql: Server: Options unspecified vulnerability (CPU Apr 2021) (CVE-2021-2146)

  - mysql: Server: Optimizer unspecified vulnerability (CPU Apr 2021) (CVE-2021-2164, CVE-2021-2169,
    CVE-2021-2170, CVE-2021-2193, CVE-2021-2203, CVE-2021-2212, CVE-2021-2213, CVE-2021-2230, CVE-2021-2278,
    CVE-2021-2298, CVE-2021-2299)

  - mysql: Server: DML unspecified vulnerability (CPU Apr 2021) (CVE-2021-2166, CVE-2021-2172, CVE-2021-2196,
    CVE-2021-2300, CVE-2021-2305)

  - mysql: Server: Replication unspecified vulnerability (CPU Apr 2021) (CVE-2021-2171, CVE-2021-2178,
    CVE-2021-2202)

  - mysql: InnoDB unspecified vulnerability (CPU Apr 2021) (CVE-2021-2174, CVE-2021-2180, CVE-2021-2194)

  - mysql: Server: Group Replication Plugin unspecified vulnerability (CPU Apr 2021) (CVE-2021-2179,
    CVE-2021-2232)

  - mysql: Server: Partition unspecified vulnerability (CPU Apr 2021) (CVE-2021-2201, CVE-2021-2208)

  - mysql: Server: Stored Procedure unspecified vulnerability (CPU Apr 2021) (CVE-2021-2215, CVE-2021-2217,
    CVE-2021-2293, CVE-2021-2304)

  - mysql: Server: Information Schema unspecified vulnerability (CPU Apr 2021) (CVE-2021-2226, CVE-2021-2301,
    CVE-2021-2308)

  - mysql: Server: Packaging unspecified vulnerability (CPU Apr 2021) (CVE-2021-2307)

  - mysql: Server: DDL unspecified vulnerability (CPU Jul 2021) (CVE-2021-2339, CVE-2021-2352, CVE-2021-2399)

  - mysql: Server: Memcached unspecified vulnerability (CPU Jul 2021) (CVE-2021-2340)

  - mysql: Server: Optimizer unspecified vulnerability (CPU Jul 2021) (CVE-2021-2342, CVE-2021-2357,
    CVE-2021-2367, CVE-2021-2383, CVE-2021-2384, CVE-2021-2387, CVE-2021-2410, CVE-2021-2412, CVE-2021-2418,
    CVE-2021-2425, CVE-2021-2426, CVE-2021-2427, CVE-2021-2437, CVE-2021-2441, CVE-2021-2444)

  - mysql: Server: Federated unspecified vulnerability (CPU Jul 2021) (CVE-2021-2354)

  - mysql: Server: Replication unspecified vulnerability (CPU Jul 2021) (CVE-2021-2356, CVE-2021-2385)

  - mysql: Server: DML unspecified vulnerability (CPU Jul 2021) (CVE-2021-2370, CVE-2021-2440)

  - mysql: InnoDB unspecified vulnerability (CPU Jul 2021) (CVE-2021-2372, CVE-2021-2374, CVE-2021-2389,
    CVE-2021-2390, CVE-2021-2429)

  - mysql: Server: Locking unspecified vulnerability (CPU Jul 2021) (CVE-2021-2402)

  - mysql: Server: GIS unspecified vulnerability (CPU Jul 2021) (CVE-2021-2417)

  - mysql: Server: PS unspecified vulnerability (CPU Jul 2021) (CVE-2021-2422)

  - mysql: Server: Stored Procedure unspecified vulnerability (CPU Jul 2021) (CVE-2021-2424)

  - mysql: Server: DML unspecified vulnerability (CPU Oct 2021) (CVE-2021-35537)

  - mysql: Server: Optimizer unspecified vulnerability (CPU Oct 2021) (CVE-2021-35629)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-14672");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-14765");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-14769");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-14773");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-14775");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-14776");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-14777");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-14785");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-14786");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-14789");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-14790");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-14791");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-14793");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-14794");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-14800");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-14804");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-14809");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-14812");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-14814");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-14821");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-14828");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-14829");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-14830");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-14836");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-14837");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-14838");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-14839");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-14844");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-14845");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-14846");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-14848");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-14852");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-14860");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-14861");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-14866");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-14867");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-14868");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-14870");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-14873");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-14888");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-14891");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-14893");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2021-2001");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2021-2002");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2021-2010");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2021-2011");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2021-2021");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2021-2022");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2021-2024");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2021-2028");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2021-2030");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2021-2031");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2021-2032");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2021-2036");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2021-2038");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2021-2042");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2021-2046");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2021-2048");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2021-2055");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2021-2056");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2021-2058");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2021-2060");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2021-2061");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2021-2065");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2021-2070");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2021-2072");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2021-2076");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2021-2081");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2021-2087");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2021-2088");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2021-2122");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2021-2146");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2021-2164");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2021-2166");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2021-2169");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2021-2170");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2021-2171");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2021-2172");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2021-2174");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2021-2178");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2021-2179");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2021-2180");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2021-2193");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2021-2194");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2021-2196");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2021-2201");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2021-2202");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2021-2203");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2021-2208");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2021-2212");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2021-2213");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2021-2215");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2021-2217");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2021-2226");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2021-2230");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2021-2232");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2021-2278");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2021-2293");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2021-2298");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2021-2299");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2021-2300");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2021-2301");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2021-2304");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2021-2305");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2021-2307");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2021-2308");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2021-2339");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2021-2340");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2021-2342");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2021-2352");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2021-2354");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2021-2356");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2021-2357");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2021-2367");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2021-2370");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2021-2372");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2021-2374");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2021-2383");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2021-2384");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2021-2385");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2021-2387");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2021-2389");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2021-2390");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2021-2399");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2021-2402");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2021-2410");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2021-2412");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2021-2417");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2021-2418");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2021-2422");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2021-2424");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2021-2425");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2021-2426");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2021-2427");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2021-2429");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2021-2437");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2021-2440");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2021-2441");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2021-2444");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2021-35537");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2021-35629");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2021:3590");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1890737");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1890738");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1890739");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1890742");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1890743");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1890744");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1890745");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1890746");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1890747");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1890748");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1890749");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1890750");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1890751");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1890753");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1890754");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1890755");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1890756");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1890757");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1890758");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1890760");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1890761");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1890762");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1890763");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1890764");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1890765");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1890766");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1890767");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1890768");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1890769");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1890770");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1890771");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1890772");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1890773");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1890774");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1890775");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1890776");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1890778");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1890779");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1890781");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1890782");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1890783");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1890784");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1922379");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1922380");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1922383");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1922384");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1922388");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1922389");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1922390");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1922391");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1922392");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1922393");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1922394");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1922395");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1922396");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1922397");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1922398");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1922399");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1922400");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1922401");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1922402");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1922403");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1922404");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1922405");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1922406");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1922407");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1922408");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1922410");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1922411");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1922416");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1922419");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1951751");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1951754");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1951755");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1951756");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1951757");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1951758");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1951759");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1951760");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1951761");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1951762");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1951763");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1951764");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1951765");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1951766");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1951767");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1951768");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1951769");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1951770");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1951771");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1951772");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1951773");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1951774");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1951775");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1951776");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1951777");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1951778");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1951779");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1951780");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1951781");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1951782");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1951783");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1951784");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1951785");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1951786");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1952802");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1992279");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1992280");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1992294");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1992297");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1992298");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1992299");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1992300");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1992301");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1992302");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1992303");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1992304");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1992305");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1992306");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1992307");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1992308");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1992309");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1992310");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1992311");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1992312");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1992313");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1992314");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1992315");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1992316");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1992317");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1992318");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1992319");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1992320");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1992321");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1992322");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1992323");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1992324");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1992325");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1992326");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/2016092");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/2016116");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-2417");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2020-14828");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/10/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/09/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/09/21");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:8");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:rhel_aus:8.4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:rhel_aus:8.6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:rhel_e4s:8.4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:rhel_e4s:8.6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:rhel_eus:8.4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:rhel_eus:8.6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:rhel_tus:8.4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:rhel_tus:8.6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mecab");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mecab-ipadic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mecab-ipadic-EUCJP");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mysql-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mysql-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mysql-errmsg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mysql-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mysql-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mysql-test");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Red Hat Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl", "redhat_repos.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/RedHat/release", "Host/RedHat/rpm-list", "Host/cpu");

  exit(0);
}


include('rpm.inc');
include('rhel.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item('Host/RedHat/release');
if (isnull(os_release) || 'Red Hat' >!< os_release) audit(AUDIT_OS_NOT, 'Red Hat');
var os_ver = pregmatch(pattern: "Red Hat Enterprise Linux.*release ([0-9]+(\.[0-9]+)?)", string:os_release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'Red Hat');
os_ver = os_ver[1];
if (!rhel_check_release(operator: 'ge', os_version: os_ver, rhel_version: '8')) audit(AUDIT_OS_NOT, 'Red Hat 8.x', 'Red Hat ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu && 'ppc' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Red Hat', cpu);

var appstreams = {
  'mysql:8.0': [
    {
      'repo_relative_urls': [
        'content/aus/rhel8/8.4/x86_64/appstream/debug',
        'content/aus/rhel8/8.4/x86_64/appstream/os',
        'content/aus/rhel8/8.4/x86_64/appstream/source/SRPMS',
        'content/aus/rhel8/8.4/x86_64/baseos/debug',
        'content/aus/rhel8/8.4/x86_64/baseos/os',
        'content/aus/rhel8/8.4/x86_64/baseos/source/SRPMS',
        'content/e4s/rhel8/8.4/aarch64/appstream/debug',
        'content/e4s/rhel8/8.4/aarch64/appstream/os',
        'content/e4s/rhel8/8.4/aarch64/appstream/source/SRPMS',
        'content/e4s/rhel8/8.4/aarch64/baseos/debug',
        'content/e4s/rhel8/8.4/aarch64/baseos/os',
        'content/e4s/rhel8/8.4/aarch64/baseos/source/SRPMS',
        'content/e4s/rhel8/8.4/ppc64le/appstream/debug',
        'content/e4s/rhel8/8.4/ppc64le/appstream/os',
        'content/e4s/rhel8/8.4/ppc64le/appstream/source/SRPMS',
        'content/e4s/rhel8/8.4/ppc64le/baseos/debug',
        'content/e4s/rhel8/8.4/ppc64le/baseos/os',
        'content/e4s/rhel8/8.4/ppc64le/baseos/source/SRPMS',
        'content/e4s/rhel8/8.4/ppc64le/highavailability/debug',
        'content/e4s/rhel8/8.4/ppc64le/highavailability/os',
        'content/e4s/rhel8/8.4/ppc64le/highavailability/source/SRPMS',
        'content/e4s/rhel8/8.4/ppc64le/sap-solutions/debug',
        'content/e4s/rhel8/8.4/ppc64le/sap-solutions/os',
        'content/e4s/rhel8/8.4/ppc64le/sap-solutions/source/SRPMS',
        'content/e4s/rhel8/8.4/ppc64le/sap/debug',
        'content/e4s/rhel8/8.4/ppc64le/sap/os',
        'content/e4s/rhel8/8.4/ppc64le/sap/source/SRPMS',
        'content/e4s/rhel8/8.4/s390x/appstream/debug',
        'content/e4s/rhel8/8.4/s390x/appstream/os',
        'content/e4s/rhel8/8.4/s390x/appstream/source/SRPMS',
        'content/e4s/rhel8/8.4/s390x/baseos/debug',
        'content/e4s/rhel8/8.4/s390x/baseos/os',
        'content/e4s/rhel8/8.4/s390x/baseos/source/SRPMS',
        'content/e4s/rhel8/8.4/x86_64/appstream/debug',
        'content/e4s/rhel8/8.4/x86_64/appstream/os',
        'content/e4s/rhel8/8.4/x86_64/appstream/source/SRPMS',
        'content/e4s/rhel8/8.4/x86_64/baseos/debug',
        'content/e4s/rhel8/8.4/x86_64/baseos/os',
        'content/e4s/rhel8/8.4/x86_64/baseos/source/SRPMS',
        'content/e4s/rhel8/8.4/x86_64/highavailability/debug',
        'content/e4s/rhel8/8.4/x86_64/highavailability/os',
        'content/e4s/rhel8/8.4/x86_64/highavailability/source/SRPMS',
        'content/e4s/rhel8/8.4/x86_64/nfv/debug',
        'content/e4s/rhel8/8.4/x86_64/nfv/os',
        'content/e4s/rhel8/8.4/x86_64/nfv/source/SRPMS',
        'content/e4s/rhel8/8.4/x86_64/sap-solutions/debug',
        'content/e4s/rhel8/8.4/x86_64/sap-solutions/os',
        'content/e4s/rhel8/8.4/x86_64/sap-solutions/source/SRPMS',
        'content/e4s/rhel8/8.4/x86_64/sap/debug',
        'content/e4s/rhel8/8.4/x86_64/sap/os',
        'content/e4s/rhel8/8.4/x86_64/sap/source/SRPMS',
        'content/eus/rhel8/8.4/aarch64/appstream/debug',
        'content/eus/rhel8/8.4/aarch64/appstream/os',
        'content/eus/rhel8/8.4/aarch64/appstream/source/SRPMS',
        'content/eus/rhel8/8.4/aarch64/baseos/debug',
        'content/eus/rhel8/8.4/aarch64/baseos/os',
        'content/eus/rhel8/8.4/aarch64/baseos/source/SRPMS',
        'content/eus/rhel8/8.4/aarch64/codeready-builder/debug',
        'content/eus/rhel8/8.4/aarch64/codeready-builder/os',
        'content/eus/rhel8/8.4/aarch64/codeready-builder/source/SRPMS',
        'content/eus/rhel8/8.4/aarch64/highavailability/debug',
        'content/eus/rhel8/8.4/aarch64/highavailability/os',
        'content/eus/rhel8/8.4/aarch64/highavailability/source/SRPMS',
        'content/eus/rhel8/8.4/aarch64/supplementary/debug',
        'content/eus/rhel8/8.4/aarch64/supplementary/os',
        'content/eus/rhel8/8.4/aarch64/supplementary/source/SRPMS',
        'content/eus/rhel8/8.4/ppc64le/appstream/debug',
        'content/eus/rhel8/8.4/ppc64le/appstream/os',
        'content/eus/rhel8/8.4/ppc64le/appstream/source/SRPMS',
        'content/eus/rhel8/8.4/ppc64le/baseos/debug',
        'content/eus/rhel8/8.4/ppc64le/baseos/os',
        'content/eus/rhel8/8.4/ppc64le/baseos/source/SRPMS',
        'content/eus/rhel8/8.4/ppc64le/codeready-builder/debug',
        'content/eus/rhel8/8.4/ppc64le/codeready-builder/os',
        'content/eus/rhel8/8.4/ppc64le/codeready-builder/source/SRPMS',
        'content/eus/rhel8/8.4/ppc64le/highavailability/debug',
        'content/eus/rhel8/8.4/ppc64le/highavailability/os',
        'content/eus/rhel8/8.4/ppc64le/highavailability/source/SRPMS',
        'content/eus/rhel8/8.4/ppc64le/resilientstorage/debug',
        'content/eus/rhel8/8.4/ppc64le/resilientstorage/os',
        'content/eus/rhel8/8.4/ppc64le/resilientstorage/source/SRPMS',
        'content/eus/rhel8/8.4/ppc64le/sap-solutions/debug',
        'content/eus/rhel8/8.4/ppc64le/sap-solutions/os',
        'content/eus/rhel8/8.4/ppc64le/sap-solutions/source/SRPMS',
        'content/eus/rhel8/8.4/ppc64le/sap/debug',
        'content/eus/rhel8/8.4/ppc64le/sap/os',
        'content/eus/rhel8/8.4/ppc64le/sap/source/SRPMS',
        'content/eus/rhel8/8.4/ppc64le/supplementary/debug',
        'content/eus/rhel8/8.4/ppc64le/supplementary/os',
        'content/eus/rhel8/8.4/ppc64le/supplementary/source/SRPMS',
        'content/eus/rhel8/8.4/s390x/appstream/debug',
        'content/eus/rhel8/8.4/s390x/appstream/os',
        'content/eus/rhel8/8.4/s390x/appstream/source/SRPMS',
        'content/eus/rhel8/8.4/s390x/baseos/debug',
        'content/eus/rhel8/8.4/s390x/baseos/os',
        'content/eus/rhel8/8.4/s390x/baseos/source/SRPMS',
        'content/eus/rhel8/8.4/s390x/codeready-builder/debug',
        'content/eus/rhel8/8.4/s390x/codeready-builder/os',
        'content/eus/rhel8/8.4/s390x/codeready-builder/source/SRPMS',
        'content/eus/rhel8/8.4/s390x/highavailability/debug',
        'content/eus/rhel8/8.4/s390x/highavailability/os',
        'content/eus/rhel8/8.4/s390x/highavailability/source/SRPMS',
        'content/eus/rhel8/8.4/s390x/resilientstorage/debug',
        'content/eus/rhel8/8.4/s390x/resilientstorage/os',
        'content/eus/rhel8/8.4/s390x/resilientstorage/source/SRPMS',
        'content/eus/rhel8/8.4/s390x/sap/debug',
        'content/eus/rhel8/8.4/s390x/sap/os',
        'content/eus/rhel8/8.4/s390x/sap/source/SRPMS',
        'content/eus/rhel8/8.4/s390x/supplementary/debug',
        'content/eus/rhel8/8.4/s390x/supplementary/os',
        'content/eus/rhel8/8.4/s390x/supplementary/source/SRPMS',
        'content/eus/rhel8/8.4/x86_64/appstream/debug',
        'content/eus/rhel8/8.4/x86_64/appstream/os',
        'content/eus/rhel8/8.4/x86_64/appstream/source/SRPMS',
        'content/eus/rhel8/8.4/x86_64/baseos/debug',
        'content/eus/rhel8/8.4/x86_64/baseos/os',
        'content/eus/rhel8/8.4/x86_64/baseos/source/SRPMS',
        'content/eus/rhel8/8.4/x86_64/codeready-builder/debug',
        'content/eus/rhel8/8.4/x86_64/codeready-builder/os',
        'content/eus/rhel8/8.4/x86_64/codeready-builder/source/SRPMS',
        'content/eus/rhel8/8.4/x86_64/highavailability/debug',
        'content/eus/rhel8/8.4/x86_64/highavailability/os',
        'content/eus/rhel8/8.4/x86_64/highavailability/source/SRPMS',
        'content/eus/rhel8/8.4/x86_64/resilientstorage/debug',
        'content/eus/rhel8/8.4/x86_64/resilientstorage/os',
        'content/eus/rhel8/8.4/x86_64/resilientstorage/source/SRPMS',
        'content/eus/rhel8/8.4/x86_64/sap-solutions/debug',
        'content/eus/rhel8/8.4/x86_64/sap-solutions/os',
        'content/eus/rhel8/8.4/x86_64/sap-solutions/source/SRPMS',
        'content/eus/rhel8/8.4/x86_64/sap/debug',
        'content/eus/rhel8/8.4/x86_64/sap/os',
        'content/eus/rhel8/8.4/x86_64/sap/source/SRPMS',
        'content/eus/rhel8/8.4/x86_64/supplementary/debug',
        'content/eus/rhel8/8.4/x86_64/supplementary/os',
        'content/eus/rhel8/8.4/x86_64/supplementary/source/SRPMS',
        'content/tus/rhel8/8.4/x86_64/appstream/debug',
        'content/tus/rhel8/8.4/x86_64/appstream/os',
        'content/tus/rhel8/8.4/x86_64/appstream/source/SRPMS',
        'content/tus/rhel8/8.4/x86_64/baseos/debug',
        'content/tus/rhel8/8.4/x86_64/baseos/os',
        'content/tus/rhel8/8.4/x86_64/baseos/source/SRPMS',
        'content/tus/rhel8/8.4/x86_64/highavailability/debug',
        'content/tus/rhel8/8.4/x86_64/highavailability/os',
        'content/tus/rhel8/8.4/x86_64/highavailability/source/SRPMS',
        'content/tus/rhel8/8.4/x86_64/nfv/debug',
        'content/tus/rhel8/8.4/x86_64/nfv/os',
        'content/tus/rhel8/8.4/x86_64/nfv/source/SRPMS',
        'content/tus/rhel8/8.4/x86_64/rt/debug',
        'content/tus/rhel8/8.4/x86_64/rt/os',
        'content/tus/rhel8/8.4/x86_64/rt/source/SRPMS'
      ],
      'pkgs': [
        {'reference':'mecab-0.996-1.module+el8.0.0+3898+e09bb8de.9', 'sp':'4', 'release':'8', 'el_string':'el8.0.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'mecab-ipadic-2.7.0.20070801-16.module+el8.0.0+3898+e09bb8de', 'sp':'4', 'release':'8', 'el_string':'el8.0.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'mecab-ipadic-EUCJP-2.7.0.20070801-16.module+el8.0.0+3898+e09bb8de', 'sp':'4', 'release':'8', 'el_string':'el8.0.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'mysql-8.0.26-1.module+el8.4.0+12359+b8928c02', 'sp':'4', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'mysql-common-8.0.26-1.module+el8.4.0+12359+b8928c02', 'sp':'4', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'mysql-devel-8.0.26-1.module+el8.4.0+12359+b8928c02', 'sp':'4', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'mysql-errmsg-8.0.26-1.module+el8.4.0+12359+b8928c02', 'sp':'4', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'mysql-libs-8.0.26-1.module+el8.4.0+12359+b8928c02', 'sp':'4', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'mysql-server-8.0.26-1.module+el8.4.0+12359+b8928c02', 'sp':'4', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'mysql-test-8.0.26-1.module+el8.4.0+12359+b8928c02', 'sp':'4', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE}
      ]
    },
    {
      'repo_relative_urls': [
        'content/aus/rhel8/8.6/x86_64/appstream/debug',
        'content/aus/rhel8/8.6/x86_64/appstream/os',
        'content/aus/rhel8/8.6/x86_64/appstream/source/SRPMS',
        'content/aus/rhel8/8.6/x86_64/baseos/debug',
        'content/aus/rhel8/8.6/x86_64/baseos/os',
        'content/aus/rhel8/8.6/x86_64/baseos/source/SRPMS',
        'content/e4s/rhel8/8.6/ppc64le/appstream/debug',
        'content/e4s/rhel8/8.6/ppc64le/appstream/os',
        'content/e4s/rhel8/8.6/ppc64le/appstream/source/SRPMS',
        'content/e4s/rhel8/8.6/ppc64le/baseos/debug',
        'content/e4s/rhel8/8.6/ppc64le/baseos/os',
        'content/e4s/rhel8/8.6/ppc64le/baseos/source/SRPMS',
        'content/e4s/rhel8/8.6/ppc64le/highavailability/debug',
        'content/e4s/rhel8/8.6/ppc64le/highavailability/os',
        'content/e4s/rhel8/8.6/ppc64le/highavailability/source/SRPMS',
        'content/e4s/rhel8/8.6/ppc64le/sap-solutions/debug',
        'content/e4s/rhel8/8.6/ppc64le/sap-solutions/os',
        'content/e4s/rhel8/8.6/ppc64le/sap-solutions/source/SRPMS',
        'content/e4s/rhel8/8.6/ppc64le/sap/debug',
        'content/e4s/rhel8/8.6/ppc64le/sap/os',
        'content/e4s/rhel8/8.6/ppc64le/sap/source/SRPMS',
        'content/e4s/rhel8/8.6/x86_64/appstream/debug',
        'content/e4s/rhel8/8.6/x86_64/appstream/os',
        'content/e4s/rhel8/8.6/x86_64/appstream/source/SRPMS',
        'content/e4s/rhel8/8.6/x86_64/baseos/debug',
        'content/e4s/rhel8/8.6/x86_64/baseos/os',
        'content/e4s/rhel8/8.6/x86_64/baseos/source/SRPMS',
        'content/e4s/rhel8/8.6/x86_64/highavailability/debug',
        'content/e4s/rhel8/8.6/x86_64/highavailability/os',
        'content/e4s/rhel8/8.6/x86_64/highavailability/source/SRPMS',
        'content/e4s/rhel8/8.6/x86_64/sap-solutions/debug',
        'content/e4s/rhel8/8.6/x86_64/sap-solutions/os',
        'content/e4s/rhel8/8.6/x86_64/sap-solutions/source/SRPMS',
        'content/e4s/rhel8/8.6/x86_64/sap/debug',
        'content/e4s/rhel8/8.6/x86_64/sap/os',
        'content/e4s/rhel8/8.6/x86_64/sap/source/SRPMS',
        'content/eus/rhel8/8.6/aarch64/appstream/debug',
        'content/eus/rhel8/8.6/aarch64/appstream/os',
        'content/eus/rhel8/8.6/aarch64/appstream/source/SRPMS',
        'content/eus/rhel8/8.6/aarch64/baseos/debug',
        'content/eus/rhel8/8.6/aarch64/baseos/os',
        'content/eus/rhel8/8.6/aarch64/baseos/source/SRPMS',
        'content/eus/rhel8/8.6/aarch64/codeready-builder/debug',
        'content/eus/rhel8/8.6/aarch64/codeready-builder/os',
        'content/eus/rhel8/8.6/aarch64/codeready-builder/source/SRPMS',
        'content/eus/rhel8/8.6/aarch64/highavailability/debug',
        'content/eus/rhel8/8.6/aarch64/highavailability/os',
        'content/eus/rhel8/8.6/aarch64/highavailability/source/SRPMS',
        'content/eus/rhel8/8.6/aarch64/supplementary/debug',
        'content/eus/rhel8/8.6/aarch64/supplementary/os',
        'content/eus/rhel8/8.6/aarch64/supplementary/source/SRPMS',
        'content/eus/rhel8/8.6/ppc64le/appstream/debug',
        'content/eus/rhel8/8.6/ppc64le/appstream/os',
        'content/eus/rhel8/8.6/ppc64le/appstream/source/SRPMS',
        'content/eus/rhel8/8.6/ppc64le/baseos/debug',
        'content/eus/rhel8/8.6/ppc64le/baseos/os',
        'content/eus/rhel8/8.6/ppc64le/baseos/source/SRPMS',
        'content/eus/rhel8/8.6/ppc64le/codeready-builder/debug',
        'content/eus/rhel8/8.6/ppc64le/codeready-builder/os',
        'content/eus/rhel8/8.6/ppc64le/codeready-builder/source/SRPMS',
        'content/eus/rhel8/8.6/ppc64le/highavailability/debug',
        'content/eus/rhel8/8.6/ppc64le/highavailability/os',
        'content/eus/rhel8/8.6/ppc64le/highavailability/source/SRPMS',
        'content/eus/rhel8/8.6/ppc64le/resilientstorage/debug',
        'content/eus/rhel8/8.6/ppc64le/resilientstorage/os',
        'content/eus/rhel8/8.6/ppc64le/resilientstorage/source/SRPMS',
        'content/eus/rhel8/8.6/ppc64le/sap-solutions/debug',
        'content/eus/rhel8/8.6/ppc64le/sap-solutions/os',
        'content/eus/rhel8/8.6/ppc64le/sap-solutions/source/SRPMS',
        'content/eus/rhel8/8.6/ppc64le/sap/debug',
        'content/eus/rhel8/8.6/ppc64le/sap/os',
        'content/eus/rhel8/8.6/ppc64le/sap/source/SRPMS',
        'content/eus/rhel8/8.6/ppc64le/supplementary/debug',
        'content/eus/rhel8/8.6/ppc64le/supplementary/os',
        'content/eus/rhel8/8.6/ppc64le/supplementary/source/SRPMS',
        'content/eus/rhel8/8.6/s390x/appstream/debug',
        'content/eus/rhel8/8.6/s390x/appstream/os',
        'content/eus/rhel8/8.6/s390x/appstream/source/SRPMS',
        'content/eus/rhel8/8.6/s390x/baseos/debug',
        'content/eus/rhel8/8.6/s390x/baseos/os',
        'content/eus/rhel8/8.6/s390x/baseos/source/SRPMS',
        'content/eus/rhel8/8.6/s390x/codeready-builder/debug',
        'content/eus/rhel8/8.6/s390x/codeready-builder/os',
        'content/eus/rhel8/8.6/s390x/codeready-builder/source/SRPMS',
        'content/eus/rhel8/8.6/s390x/highavailability/debug',
        'content/eus/rhel8/8.6/s390x/highavailability/os',
        'content/eus/rhel8/8.6/s390x/highavailability/source/SRPMS',
        'content/eus/rhel8/8.6/s390x/resilientstorage/debug',
        'content/eus/rhel8/8.6/s390x/resilientstorage/os',
        'content/eus/rhel8/8.6/s390x/resilientstorage/source/SRPMS',
        'content/eus/rhel8/8.6/s390x/sap/debug',
        'content/eus/rhel8/8.6/s390x/sap/os',
        'content/eus/rhel8/8.6/s390x/sap/source/SRPMS',
        'content/eus/rhel8/8.6/s390x/supplementary/debug',
        'content/eus/rhel8/8.6/s390x/supplementary/os',
        'content/eus/rhel8/8.6/s390x/supplementary/source/SRPMS',
        'content/eus/rhel8/8.6/x86_64/appstream/debug',
        'content/eus/rhel8/8.6/x86_64/appstream/os',
        'content/eus/rhel8/8.6/x86_64/appstream/source/SRPMS',
        'content/eus/rhel8/8.6/x86_64/baseos/debug',
        'content/eus/rhel8/8.6/x86_64/baseos/os',
        'content/eus/rhel8/8.6/x86_64/baseos/source/SRPMS',
        'content/eus/rhel8/8.6/x86_64/codeready-builder/debug',
        'content/eus/rhel8/8.6/x86_64/codeready-builder/os',
        'content/eus/rhel8/8.6/x86_64/codeready-builder/source/SRPMS',
        'content/eus/rhel8/8.6/x86_64/highavailability/debug',
        'content/eus/rhel8/8.6/x86_64/highavailability/os',
        'content/eus/rhel8/8.6/x86_64/highavailability/source/SRPMS',
        'content/eus/rhel8/8.6/x86_64/resilientstorage/debug',
        'content/eus/rhel8/8.6/x86_64/resilientstorage/os',
        'content/eus/rhel8/8.6/x86_64/resilientstorage/source/SRPMS',
        'content/eus/rhel8/8.6/x86_64/sap-solutions/debug',
        'content/eus/rhel8/8.6/x86_64/sap-solutions/os',
        'content/eus/rhel8/8.6/x86_64/sap-solutions/source/SRPMS',
        'content/eus/rhel8/8.6/x86_64/sap/debug',
        'content/eus/rhel8/8.6/x86_64/sap/os',
        'content/eus/rhel8/8.6/x86_64/sap/source/SRPMS',
        'content/eus/rhel8/8.6/x86_64/supplementary/debug',
        'content/eus/rhel8/8.6/x86_64/supplementary/os',
        'content/eus/rhel8/8.6/x86_64/supplementary/source/SRPMS',
        'content/tus/rhel8/8.6/x86_64/appstream/debug',
        'content/tus/rhel8/8.6/x86_64/appstream/os',
        'content/tus/rhel8/8.6/x86_64/appstream/source/SRPMS',
        'content/tus/rhel8/8.6/x86_64/baseos/debug',
        'content/tus/rhel8/8.6/x86_64/baseos/os',
        'content/tus/rhel8/8.6/x86_64/baseos/source/SRPMS',
        'content/tus/rhel8/8.6/x86_64/highavailability/debug',
        'content/tus/rhel8/8.6/x86_64/highavailability/os',
        'content/tus/rhel8/8.6/x86_64/highavailability/source/SRPMS',
        'content/tus/rhel8/8.6/x86_64/rt/os',
        'content/tus/rhel8/8.6/x86_64/rt/source/SRPMS'
      ],
      'pkgs': [
        {'reference':'mecab-0.996-1.module+el8.0.0+3898+e09bb8de.9', 'sp':'6', 'release':'8', 'el_string':'el8.0.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'mecab-ipadic-2.7.0.20070801-16.module+el8.0.0+3898+e09bb8de', 'sp':'6', 'release':'8', 'el_string':'el8.0.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'mecab-ipadic-EUCJP-2.7.0.20070801-16.module+el8.0.0+3898+e09bb8de', 'sp':'6', 'release':'8', 'el_string':'el8.0.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'mysql-8.0.26-1.module+el8.4.0+12359+b8928c02', 'sp':'6', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'mysql-common-8.0.26-1.module+el8.4.0+12359+b8928c02', 'sp':'6', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'mysql-devel-8.0.26-1.module+el8.4.0+12359+b8928c02', 'sp':'6', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'mysql-errmsg-8.0.26-1.module+el8.4.0+12359+b8928c02', 'sp':'6', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'mysql-libs-8.0.26-1.module+el8.4.0+12359+b8928c02', 'sp':'6', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'mysql-server-8.0.26-1.module+el8.4.0+12359+b8928c02', 'sp':'6', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'mysql-test-8.0.26-1.module+el8.4.0+12359+b8928c02', 'sp':'6', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE}
      ]
    },
    {
      'repo_relative_urls': [
        'content/dist/rhel8/8/aarch64/appstream/debug',
        'content/dist/rhel8/8/aarch64/appstream/os',
        'content/dist/rhel8/8/aarch64/appstream/source/SRPMS',
        'content/dist/rhel8/8/aarch64/baseos/debug',
        'content/dist/rhel8/8/aarch64/baseos/os',
        'content/dist/rhel8/8/aarch64/baseos/source/SRPMS',
        'content/dist/rhel8/8/aarch64/codeready-builder/debug',
        'content/dist/rhel8/8/aarch64/codeready-builder/os',
        'content/dist/rhel8/8/aarch64/codeready-builder/source/SRPMS',
        'content/dist/rhel8/8/aarch64/highavailability/debug',
        'content/dist/rhel8/8/aarch64/highavailability/os',
        'content/dist/rhel8/8/aarch64/highavailability/source/SRPMS',
        'content/dist/rhel8/8/aarch64/supplementary/debug',
        'content/dist/rhel8/8/aarch64/supplementary/os',
        'content/dist/rhel8/8/aarch64/supplementary/source/SRPMS',
        'content/dist/rhel8/8/ppc64le/appstream/debug',
        'content/dist/rhel8/8/ppc64le/appstream/os',
        'content/dist/rhel8/8/ppc64le/appstream/source/SRPMS',
        'content/dist/rhel8/8/ppc64le/baseos/debug',
        'content/dist/rhel8/8/ppc64le/baseos/os',
        'content/dist/rhel8/8/ppc64le/baseos/source/SRPMS',
        'content/dist/rhel8/8/ppc64le/codeready-builder/debug',
        'content/dist/rhel8/8/ppc64le/codeready-builder/os',
        'content/dist/rhel8/8/ppc64le/codeready-builder/source/SRPMS',
        'content/dist/rhel8/8/ppc64le/highavailability/debug',
        'content/dist/rhel8/8/ppc64le/highavailability/os',
        'content/dist/rhel8/8/ppc64le/highavailability/source/SRPMS',
        'content/dist/rhel8/8/ppc64le/resilientstorage/debug',
        'content/dist/rhel8/8/ppc64le/resilientstorage/os',
        'content/dist/rhel8/8/ppc64le/resilientstorage/source/SRPMS',
        'content/dist/rhel8/8/ppc64le/sap-solutions/debug',
        'content/dist/rhel8/8/ppc64le/sap-solutions/os',
        'content/dist/rhel8/8/ppc64le/sap-solutions/source/SRPMS',
        'content/dist/rhel8/8/ppc64le/sap/debug',
        'content/dist/rhel8/8/ppc64le/sap/os',
        'content/dist/rhel8/8/ppc64le/sap/source/SRPMS',
        'content/dist/rhel8/8/ppc64le/supplementary/debug',
        'content/dist/rhel8/8/ppc64le/supplementary/os',
        'content/dist/rhel8/8/ppc64le/supplementary/source/SRPMS',
        'content/dist/rhel8/8/s390x/appstream/debug',
        'content/dist/rhel8/8/s390x/appstream/os',
        'content/dist/rhel8/8/s390x/appstream/source/SRPMS',
        'content/dist/rhel8/8/s390x/baseos/debug',
        'content/dist/rhel8/8/s390x/baseos/os',
        'content/dist/rhel8/8/s390x/baseos/source/SRPMS',
        'content/dist/rhel8/8/s390x/codeready-builder/debug',
        'content/dist/rhel8/8/s390x/codeready-builder/os',
        'content/dist/rhel8/8/s390x/codeready-builder/source/SRPMS',
        'content/dist/rhel8/8/s390x/highavailability/debug',
        'content/dist/rhel8/8/s390x/highavailability/os',
        'content/dist/rhel8/8/s390x/highavailability/source/SRPMS',
        'content/dist/rhel8/8/s390x/resilientstorage/debug',
        'content/dist/rhel8/8/s390x/resilientstorage/os',
        'content/dist/rhel8/8/s390x/resilientstorage/source/SRPMS',
        'content/dist/rhel8/8/s390x/sap/debug',
        'content/dist/rhel8/8/s390x/sap/os',
        'content/dist/rhel8/8/s390x/sap/source/SRPMS',
        'content/dist/rhel8/8/s390x/supplementary/debug',
        'content/dist/rhel8/8/s390x/supplementary/os',
        'content/dist/rhel8/8/s390x/supplementary/source/SRPMS',
        'content/dist/rhel8/8/x86_64/appstream/debug',
        'content/dist/rhel8/8/x86_64/appstream/os',
        'content/dist/rhel8/8/x86_64/appstream/source/SRPMS',
        'content/dist/rhel8/8/x86_64/baseos/debug',
        'content/dist/rhel8/8/x86_64/baseos/os',
        'content/dist/rhel8/8/x86_64/baseos/source/SRPMS',
        'content/dist/rhel8/8/x86_64/codeready-builder/debug',
        'content/dist/rhel8/8/x86_64/codeready-builder/os',
        'content/dist/rhel8/8/x86_64/codeready-builder/source/SRPMS',
        'content/dist/rhel8/8/x86_64/highavailability/debug',
        'content/dist/rhel8/8/x86_64/highavailability/os',
        'content/dist/rhel8/8/x86_64/highavailability/source/SRPMS',
        'content/dist/rhel8/8/x86_64/nfv/debug',
        'content/dist/rhel8/8/x86_64/nfv/os',
        'content/dist/rhel8/8/x86_64/nfv/source/SRPMS',
        'content/dist/rhel8/8/x86_64/resilientstorage/debug',
        'content/dist/rhel8/8/x86_64/resilientstorage/os',
        'content/dist/rhel8/8/x86_64/resilientstorage/source/SRPMS',
        'content/dist/rhel8/8/x86_64/rt/debug',
        'content/dist/rhel8/8/x86_64/rt/os',
        'content/dist/rhel8/8/x86_64/rt/source/SRPMS',
        'content/dist/rhel8/8/x86_64/sap-solutions/debug',
        'content/dist/rhel8/8/x86_64/sap-solutions/os',
        'content/dist/rhel8/8/x86_64/sap-solutions/source/SRPMS',
        'content/dist/rhel8/8/x86_64/sap/debug',
        'content/dist/rhel8/8/x86_64/sap/os',
        'content/dist/rhel8/8/x86_64/sap/source/SRPMS',
        'content/dist/rhel8/8/x86_64/supplementary/debug',
        'content/dist/rhel8/8/x86_64/supplementary/os',
        'content/dist/rhel8/8/x86_64/supplementary/source/SRPMS'
      ],
      'pkgs': [
        {'reference':'mecab-0.996-1.module+el8.0.0+3898+e09bb8de.9', 'release':'8', 'el_string':'el8.0.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'mecab-ipadic-2.7.0.20070801-16.module+el8.0.0+3898+e09bb8de', 'release':'8', 'el_string':'el8.0.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'mecab-ipadic-EUCJP-2.7.0.20070801-16.module+el8.0.0+3898+e09bb8de', 'release':'8', 'el_string':'el8.0.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'mysql-8.0.26-1.module+el8.4.0+12359+b8928c02', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'mysql-common-8.0.26-1.module+el8.4.0+12359+b8928c02', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'mysql-devel-8.0.26-1.module+el8.4.0+12359+b8928c02', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'mysql-errmsg-8.0.26-1.module+el8.4.0+12359+b8928c02', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'mysql-libs-8.0.26-1.module+el8.4.0+12359+b8928c02', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'mysql-server-8.0.26-1.module+el8.4.0+12359+b8928c02', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'mysql-test-8.0.26-1.module+el8.4.0+12359+b8928c02', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE}
      ]
    }
  ]
};

var applicable_repo_urls = rhel_determine_applicable_repository_urls(constraints:appstreams, appstreams:TRUE);
if(applicable_repo_urls == RHEL_REPOS_NO_OVERLAP_MESSAGE) exit(0, RHEL_REPO_NOT_ENABLED);

var module_ver = get_kb_item('Host/RedHat/appstream/mysql');
if (isnull(module_ver)) audit(AUDIT_PACKAGE_NOT_INSTALLED, 'Module mysql:8.0');
if ('8.0' >!< module_ver) audit(AUDIT_PACKAGE_NOT_AFFECTED, 'Module mysql:' + module_ver);

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
    foreach var module_array ( appstreams[module] ) {
      var repo_relative_urls = NULL;
      if (!empty_or_null(module_array['repo_relative_urls'])) repo_relative_urls = module_array['repo_relative_urls'];
      var enterprise_linux_flag = rhel_repo_urls_has_content_dist_rhel(repo_urls:repo_relative_urls);
      foreach var package_array ( module_array['pkgs'] ) {
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
        if (!empty_or_null(package_array['release'])) _release = 'RHEL' + package_array['release'];
        if (!empty_or_null(package_array['sp']) && !enterprise_linux_flag) sp = package_array['sp'];
        if (!empty_or_null(package_array['cpu'])) _cpu = package_array['cpu'];
        if (!empty_or_null(package_array['el_string'])) el_string = package_array['el_string'];
        if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
        if (!empty_or_null(package_array['epoch'])) epoch = package_array['epoch'];
        if (!empty_or_null(package_array['allowmaj'])) allowmaj = package_array['allowmaj'];
        if (!empty_or_null(package_array['exists_check'])) exists_check = package_array['exists_check'];
        if (reference &&
            _release &&
            rhel_decide_repo_relative_url_check(required_repo_url_list:repo_relative_urls) &&
            (applicable_repo_urls || (!exists_check || rpm_exists(release:_release, rpm:exists_check))) &&
            rpm_check(release:_release, sp:sp, cpu:_cpu, reference:reference, epoch:epoch, el_string:el_string, rpm_spec_vers_cmp:rpm_spec_vers_cmp, allowmaj:allowmaj)) flag++;
      }
    }
  }
}

if (!appstreams_found) audit(AUDIT_PACKAGE_NOT_INSTALLED, 'Module mysql:8.0');

if (flag)
{
  var extra = NULL;
  if (empty_or_null(applicable_repo_urls)) extra = rpm_report_get() + redhat_report_repo_caveat();
  else extra = rpm_report_get();
  security_report_v4(
      port       : 0,
      severity   : SECURITY_HOLE,
      extra      : extra
  );
  exit(0);
}
else
{
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'mecab / mecab-ipadic / mecab-ipadic-EUCJP / mysql / mysql-common / etc');
}
