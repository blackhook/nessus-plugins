#%NASL_MIN_LEVEL 70300
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2021:3811. The text
# itself is copyright (C) Red Hat, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(154083);
  script_version("1.8");
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
    "CVE-2021-2444"
  );
  script_xref(name:"RHSA", value:"2021:3811");
  script_xref(name:"IAVA", value:"2021-A-0038");
  script_xref(name:"IAVA", value:"2020-A-0473-S");
  script_xref(name:"IAVA", value:"2021-A-0193");
  script_xref(name:"IAVA", value:"2021-A-0333");
  script_xref(name:"CEA-ID", value:"CEA-2021-0004");
  script_xref(name:"CEA-ID", value:"CEA-2021-0025");

  script_name(english:"RHEL 7 : rh-mysql80-mysql (RHSA-2021:3811)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Red Hat host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Redhat Enterprise Linux 7 host has packages installed that are affected by multiple vulnerabilities as
referenced in the RHSA-2021:3811 advisory.

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
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2021:3811");
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

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/10/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/10/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/10/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-mysql80-mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-mysql80-mysql-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-mysql80-mysql-config");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-mysql80-mysql-config-syspaths");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-mysql80-mysql-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-mysql80-mysql-errmsg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-mysql80-mysql-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-mysql80-mysql-server-syspaths");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-mysql80-mysql-syspaths");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-mysql80-mysql-test");
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
if (!rhel_check_release(operator: 'ge', os_version: os_ver, rhel_version: '7')) audit(AUDIT_OS_NOT, 'Red Hat 7.x', 'Red Hat ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu && 'ppc' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Red Hat', cpu);

var constraints = [
  {
    'repo_relative_urls': [
      'content/dist/rhel-alt/server/7/7Server/power9/ppc64le/rhscl/1/debug',
      'content/dist/rhel-alt/server/7/7Server/power9/ppc64le/rhscl/1/os',
      'content/dist/rhel-alt/server/7/7Server/power9/ppc64le/rhscl/1/source/SRPMS',
      'content/dist/rhel-alt/server/7/7Server/system-z-a/s390x/rhscl/1/debug',
      'content/dist/rhel-alt/server/7/7Server/system-z-a/s390x/rhscl/1/os',
      'content/dist/rhel-alt/server/7/7Server/system-z-a/s390x/rhscl/1/source/SRPMS',
      'content/dist/rhel/power-le/7/7Server/ppc64le/rhscl/1/debug',
      'content/dist/rhel/power-le/7/7Server/ppc64le/rhscl/1/os',
      'content/dist/rhel/power-le/7/7Server/ppc64le/rhscl/1/source/SRPMS',
      'content/dist/rhel/power/7/7Server/ppc64/rhscl/1/debug',
      'content/dist/rhel/power/7/7Server/ppc64/rhscl/1/os',
      'content/dist/rhel/power/7/7Server/ppc64/rhscl/1/source/SRPMS',
      'content/dist/rhel/server/7/7Server/x86_64/rhscl/1/debug',
      'content/dist/rhel/server/7/7Server/x86_64/rhscl/1/os',
      'content/dist/rhel/server/7/7Server/x86_64/rhscl/1/source/SRPMS',
      'content/dist/rhel/system-z/7/7Server/s390x/rhscl/1/debug',
      'content/dist/rhel/system-z/7/7Server/s390x/rhscl/1/os',
      'content/dist/rhel/system-z/7/7Server/s390x/rhscl/1/source/SRPMS',
      'content/dist/rhel/workstation/7/7Workstation/x86_64/rhscl/1/debug',
      'content/dist/rhel/workstation/7/7Workstation/x86_64/rhscl/1/os',
      'content/dist/rhel/workstation/7/7Workstation/x86_64/rhscl/1/source/SRPMS'
    ],
    'pkgs': [
      {'reference':'rh-mysql80-mysql-8.0.26-1.el7', 'cpu':'ppc64le', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-mysql80-mysql-8.0.26-1.el7', 'cpu':'s390x', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-mysql80-mysql-8.0.26-1.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-mysql80-mysql-common-8.0.26-1.el7', 'cpu':'ppc64le', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-mysql80-mysql-common-8.0.26-1.el7', 'cpu':'s390x', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-mysql80-mysql-common-8.0.26-1.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-mysql80-mysql-config-8.0.26-1.el7', 'cpu':'ppc64le', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-mysql80-mysql-config-8.0.26-1.el7', 'cpu':'s390x', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-mysql80-mysql-config-8.0.26-1.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-mysql80-mysql-config-syspaths-8.0.26-1.el7', 'cpu':'ppc64le', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-mysql80-mysql-config-syspaths-8.0.26-1.el7', 'cpu':'s390x', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-mysql80-mysql-config-syspaths-8.0.26-1.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-mysql80-mysql-devel-8.0.26-1.el7', 'cpu':'ppc64le', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-mysql80-mysql-devel-8.0.26-1.el7', 'cpu':'s390x', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-mysql80-mysql-devel-8.0.26-1.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-mysql80-mysql-errmsg-8.0.26-1.el7', 'cpu':'ppc64le', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-mysql80-mysql-errmsg-8.0.26-1.el7', 'cpu':'s390x', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-mysql80-mysql-errmsg-8.0.26-1.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-mysql80-mysql-server-8.0.26-1.el7', 'cpu':'ppc64le', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-mysql80-mysql-server-8.0.26-1.el7', 'cpu':'s390x', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-mysql80-mysql-server-8.0.26-1.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-mysql80-mysql-server-syspaths-8.0.26-1.el7', 'cpu':'ppc64le', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-mysql80-mysql-server-syspaths-8.0.26-1.el7', 'cpu':'s390x', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-mysql80-mysql-server-syspaths-8.0.26-1.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-mysql80-mysql-syspaths-8.0.26-1.el7', 'cpu':'ppc64le', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-mysql80-mysql-syspaths-8.0.26-1.el7', 'cpu':'s390x', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-mysql80-mysql-syspaths-8.0.26-1.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-mysql80-mysql-test-8.0.26-1.el7', 'cpu':'ppc64le', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-mysql80-mysql-test-8.0.26-1.el7', 'cpu':'s390x', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-mysql80-mysql-test-8.0.26-1.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE}
    ]
  }
];

var applicable_repo_urls = rhel_determine_applicable_repository_urls(constraints:constraints);
if(applicable_repo_urls == RHEL_REPOS_NO_OVERLAP_MESSAGE) exit(0, RHEL_REPO_NOT_ENABLED);

var flag = 0;
foreach var constraint_array ( constraints ) {
  var repo_relative_urls = NULL;
  if (!empty_or_null(constraint_array['repo_relative_urls'])) repo_relative_urls = constraint_array['repo_relative_urls'];
  foreach var pkg ( constraint_array['pkgs'] ) {
    var reference = NULL;
    var _release = NULL;
    var sp = NULL;
    var _cpu = NULL;
    var el_string = NULL;
    var rpm_spec_vers_cmp = NULL;
    var epoch = NULL;
    var allowmaj = NULL;
    var exists_check = NULL;
    if (!empty_or_null(pkg['reference'])) reference = pkg['reference'];
    if (!empty_or_null(pkg['release'])) _release = 'RHEL' + pkg['release'];
    if (!empty_or_null(pkg['sp'])) sp = pkg['sp'];
    if (!empty_or_null(pkg['cpu'])) _cpu = pkg['cpu'];
    if (!empty_or_null(pkg['el_string'])) el_string = pkg['el_string'];
    if (!empty_or_null(pkg['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = pkg['rpm_spec_vers_cmp'];
    if (!empty_or_null(pkg['epoch'])) epoch = pkg['epoch'];
    if (!empty_or_null(pkg['allowmaj'])) allowmaj = pkg['allowmaj'];
    if (!empty_or_null(pkg['exists_check'])) exists_check = pkg['exists_check'];
    if (reference &&
        _release &&
        rhel_decide_repo_relative_url_check(required_repo_url_list:repo_relative_urls) &&
        (applicable_repo_urls || (!exists_check || rpm_exists(release:_release, rpm:exists_check))) &&
        rpm_check(release:_release, sp:sp, cpu:_cpu, reference:reference, epoch:epoch, el_string:el_string, rpm_spec_vers_cmp:rpm_spec_vers_cmp, allowmaj:allowmaj)) flag++;
  }
}

if (flag)
{
  var extra = NULL;
  if (empty_or_null(applicable_repo_urls)) extra = rpm_report_get() + redhat_report_repo_caveat();
  else extra = rpm_report_get() + redhat_report_package_caveat();
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'rh-mysql80-mysql / rh-mysql80-mysql-common / rh-mysql80-mysql-config / etc');
}
