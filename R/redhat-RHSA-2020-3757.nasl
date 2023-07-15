##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2020:3757. The text
# itself is copyright (C) Red Hat, Inc.
##

include('compat.inc');

if (description)
{
  script_id(140599);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/25");

  script_cve_id(
    "CVE-2019-2911",
    "CVE-2019-2914",
    "CVE-2019-2938",
    "CVE-2019-2946",
    "CVE-2019-2957",
    "CVE-2019-2960",
    "CVE-2019-2963",
    "CVE-2019-2966",
    "CVE-2019-2967",
    "CVE-2019-2968",
    "CVE-2019-2974",
    "CVE-2019-2982",
    "CVE-2019-2991",
    "CVE-2019-2993",
    "CVE-2019-2997",
    "CVE-2019-2998",
    "CVE-2019-3004",
    "CVE-2019-3009",
    "CVE-2019-3011",
    "CVE-2019-3018",
    "CVE-2020-2570",
    "CVE-2020-2573",
    "CVE-2020-2574",
    "CVE-2020-2577",
    "CVE-2020-2579",
    "CVE-2020-2580",
    "CVE-2020-2584",
    "CVE-2020-2588",
    "CVE-2020-2589",
    "CVE-2020-2627",
    "CVE-2020-2660",
    "CVE-2020-2679",
    "CVE-2020-2686",
    "CVE-2020-2694",
    "CVE-2020-2752",
    "CVE-2020-2759",
    "CVE-2020-2760",
    "CVE-2020-2761",
    "CVE-2020-2762",
    "CVE-2020-2763",
    "CVE-2020-2765",
    "CVE-2020-2770",
    "CVE-2020-2774",
    "CVE-2020-2779",
    "CVE-2020-2780",
    "CVE-2020-2804",
    "CVE-2020-2812",
    "CVE-2020-2814",
    "CVE-2020-2853",
    "CVE-2020-2892",
    "CVE-2020-2893",
    "CVE-2020-2895",
    "CVE-2020-2896",
    "CVE-2020-2897",
    "CVE-2020-2898",
    "CVE-2020-2901",
    "CVE-2020-2903",
    "CVE-2020-2904",
    "CVE-2020-2921",
    "CVE-2020-2922",
    "CVE-2020-2923",
    "CVE-2020-2924",
    "CVE-2020-2925",
    "CVE-2020-2926",
    "CVE-2020-2928",
    "CVE-2020-2930",
    "CVE-2020-14539",
    "CVE-2020-14540",
    "CVE-2020-14547",
    "CVE-2020-14550",
    "CVE-2020-14553",
    "CVE-2020-14559",
    "CVE-2020-14567",
    "CVE-2020-14568",
    "CVE-2020-14575",
    "CVE-2020-14576",
    "CVE-2020-14586",
    "CVE-2020-14597",
    "CVE-2020-14614",
    "CVE-2020-14619",
    "CVE-2020-14620",
    "CVE-2020-14623",
    "CVE-2020-14624",
    "CVE-2020-14631",
    "CVE-2020-14632",
    "CVE-2020-14633",
    "CVE-2020-14634",
    "CVE-2020-14641",
    "CVE-2020-14643",
    "CVE-2020-14651",
    "CVE-2020-14654",
    "CVE-2020-14656",
    "CVE-2020-14663",
    "CVE-2020-14678",
    "CVE-2020-14680",
    "CVE-2020-14697",
    "CVE-2020-14702",
    "CVE-2020-14725",
    "CVE-2020-14799",
    "CVE-2021-1998",
    "CVE-2021-2006",
    "CVE-2021-2007",
    "CVE-2021-2009",
    "CVE-2021-2012",
    "CVE-2021-2016",
    "CVE-2021-2019",
    "CVE-2021-2020",
    "CVE-2021-2144",
    "CVE-2021-2160"
  );
  script_xref(name:"IAVA", value:"2020-A-0143");
  script_xref(name:"IAVA", value:"2020-A-0321");
  script_xref(name:"IAVA", value:"2021-A-0038");
  script_xref(name:"IAVA", value:"2020-A-0473-S");
  script_xref(name:"IAVA", value:"2021-A-0193");
  script_xref(name:"IAVA", value:"2019-A-0383-S");
  script_xref(name:"IAVA", value:"2020-A-0021-S");
  script_xref(name:"RHSA", value:"2020:3757");
  script_xref(name:"CEA-ID", value:"CEA-2021-0025");
  script_xref(name:"CEA-ID", value:"CEA-2021-0004");

  script_name(english:"RHEL 8 : mysql:8.0 (RHSA-2020:3757)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Red Hat host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Redhat Enterprise Linux 8 host has packages installed that are affected by multiple vulnerabilities as
referenced in the RHSA-2020:3757 advisory.

  - mysql: Information Schema unspecified vulnerability (CPU Oct 2019) (CVE-2019-2911)

  - mysql: Server: Security: Encryption unspecified vulnerability (CPU Oct 2019) (CVE-2019-2914,
    CVE-2019-2957)

  - mysql: InnoDB unspecified vulnerability (CPU Oct 2019) (CVE-2019-2938, CVE-2019-2963, CVE-2019-2968,
    CVE-2019-3018)

  - mysql: Server: PS unspecified vulnerability (CPU Oct 2019) (CVE-2019-2946)

  - mysql: Server: Replication unspecified vulnerability (CPU Oct 2019) (CVE-2019-2960)

  - mysql: Server: Optimizer unspecified vulnerability (CPU Oct 2019) (CVE-2019-2966, CVE-2019-2967,
    CVE-2019-2974, CVE-2019-2982, CVE-2019-2991, CVE-2019-2998)

  - mysql: Server: C API unspecified vulnerability (CPU Oct 2019) (CVE-2019-2993, CVE-2019-3011)

  - mysql: Server: DDL unspecified vulnerability (CPU Oct 2019) (CVE-2019-2997)

  - mysql: Server: Parser unspecified vulnerability (CPU Oct 2019) (CVE-2019-3004)

  - mysql: Server: Connection unspecified vulnerability (CPU Oct 2019) (CVE-2019-3009)

  - mysql: Server: Optimizer unspecified vulnerability (CPU Jul 2020) (CVE-2020-14539, CVE-2020-14547,
    CVE-2020-14597, CVE-2020-14614, CVE-2020-14654, CVE-2020-14680, CVE-2020-14725)

  - mysql: Server: DML unspecified vulnerability (CPU Jul 2020) (CVE-2020-14540, CVE-2020-14575,
    CVE-2020-14620)

  - mysql: C API unspecified vulnerability (CPU Jul 2020) (CVE-2020-14550)

  - mysql: Server: Pluggable Auth unspecified vulnerability (CPU Jul 2020) (CVE-2020-14553)

  - mysql: Server: Information Schema unspecified vulnerability (CPU Jul 2020) (CVE-2020-14559)

  - mysql: Server: Replication unspecified vulnerability (CPU Jul 2020) (CVE-2020-14567)

  - mysql: InnoDB unspecified vulnerability (CPU Jul 2020) (CVE-2020-14568, CVE-2020-14623, CVE-2020-14633,
    CVE-2020-14634)

  - mysql: Server: UDF unspecified vulnerability (CPU Jul 2020) (CVE-2020-14576)

  - mysql: Server: Security: Privileges unspecified vulnerability (CPU Jul 2020) (CVE-2020-14586,
    CVE-2020-14663, CVE-2020-14678, CVE-2020-14697, CVE-2020-14702)

  - mysql: Server: Parser unspecified vulnerability (CPU Jul 2020) (CVE-2020-14619)

  - mysql: Server: JSON unspecified vulnerability (CPU Jul 2020) (CVE-2020-14624)

  - mysql: Server: Security: Audit unspecified vulnerability (CPU Jul 2020) (CVE-2020-14631)

  - mysql: Server: Options unspecified vulnerability (CPU Jul 2020) (CVE-2020-14632)

  - mysql: Server: Security: Roles unspecified vulnerability (CPU Jul 2020) (CVE-2020-14641, CVE-2020-14643,
    CVE-2020-14651)

  - mysql: Server: Locking unspecified vulnerability (CPU Jul 2020) (CVE-2020-14656)

  - mysql: Server: Security: Encryption unspecified vulnerability (CPU Oct 2020) (CVE-2020-14799)

  - mysql: C API unspecified vulnerability (CPU Jan 2020) (CVE-2020-2570, CVE-2020-2573, CVE-2020-2574)

  - mysql: InnoDB unspecified vulnerability (CPU Jan 2020) (CVE-2020-2577, CVE-2020-2589)

  - mysql: Server: Optimizer unspecified vulnerability (CPU Jan 2020) (CVE-2020-2579, CVE-2020-2660,
    CVE-2020-2679, CVE-2020-2686)

  - mysql: Server: DDL unspecified vulnerability (CPU Jan 2020) (CVE-2020-2580)

  - mysql: Server: Options unspecified vulnerability (CPU Jan 2020) (CVE-2020-2584)

  - mysql: Server: DML unspecified vulnerability (CPU Jan 2020) (CVE-2020-2588)

  - mysql: Server: Parser unspecified vulnerability (CPU Jan 2020) (CVE-2020-2627)

  - mysql: Server: Information Schema unspecified vulnerability (CPU Jan 2020) (CVE-2020-2694)

  - mysql: C API unspecified vulnerability (CPU Apr 2020) (CVE-2020-2752, CVE-2020-2922)

  - mysql: Server: Replication unspecified vulnerability (CPU Apr 2020) (CVE-2020-2759, CVE-2020-2763)

  - mysql: InnoDB unspecified vulnerability (CPU Apr 2020) (CVE-2020-2760, CVE-2020-2762, CVE-2020-2814,
    CVE-2020-2893, CVE-2020-2895)

  - mysql: Server: Security: Privileges unspecified vulnerability (CPU Apr 2020) (CVE-2020-2761,
    CVE-2020-2774, CVE-2020-2779, CVE-2020-2853)

  - mysql: Server: Optimizer unspecified vulnerability (CPU Apr 2020) (CVE-2020-2765, CVE-2020-2892,
    CVE-2020-2897, CVE-2020-2901, CVE-2020-2904, CVE-2020-2923, CVE-2020-2924, CVE-2020-2928)

  - mysql: Server: Logging unspecified vulnerability (CPU Apr 2020) (CVE-2020-2770)

  - mysql: Server: DML unspecified vulnerability (CPU Apr 2020) (CVE-2020-2780)

  - mysql: Server: Memcached unspecified vulnerability (CPU Apr 2020) (CVE-2020-2804)

  - mysql: Server: Stored Procedure unspecified vulnerability (CPU Apr 2020) (CVE-2020-2812)

  - mysql: Server: Information Schema unspecified vulnerability (CPU Apr 2020) (CVE-2020-2896)

  - mysql: Server: Charsets unspecified vulnerability (CPU Apr 2020) (CVE-2020-2898)

  - mysql: Server: Connection Handling unspecified vulnerability (CPU Apr 2020) (CVE-2020-2903)

  - mysql: Server: Group Replication Plugin unspecified vulnerability (CPU Apr 2020) (CVE-2020-2921)

  - mysql: Server: PS unspecified vulnerability (CPU Apr 2020) (CVE-2020-2925)

  - mysql: Server: Group Replication GCS unspecified vulnerability (CPU Apr 2020) (CVE-2020-2926)

  - mysql: Server: Parser unspecified vulnerability (CPU Apr 2020) (CVE-2020-2930)

  - mysql: Server: Optimizer unspecified vulnerability (CPU Jan 2021) (CVE-2021-1998, CVE-2021-2016,
    CVE-2021-2020)

  - mysql: C API unspecified vulnerability (CPU Jan 2021) (CVE-2021-2006, CVE-2021-2007)

  - mysql: Server: Security: Roles unspecified vulnerability (CPU Jan 2021) (CVE-2021-2009)

  - mysql: Server: Security: Privileges unspecified vulnerability (CPU Jan 2021) (CVE-2021-2012,
    CVE-2021-2019)

  - mysql: Server: Parser unspecified vulnerability (CPU Apr 2021) (CVE-2021-2144)

  - mysql: Server: Optimizer unspecified vulnerability (CPU Apr 2021) (CVE-2021-2160)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-2911");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-2914");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-2938");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-2946");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-2957");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-2960");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-2963");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-2966");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-2967");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-2968");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-2974");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-2982");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-2991");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-2993");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-2997");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-2998");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-3004");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-3009");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-3011");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-3018");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-2570");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-2573");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-2574");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-2577");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-2579");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-2580");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-2584");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-2588");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-2589");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-2627");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-2660");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-2679");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-2686");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-2694");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-2752");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-2759");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-2760");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-2761");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-2762");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-2763");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-2765");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-2770");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-2774");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-2779");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-2780");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-2804");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-2812");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-2814");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-2853");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-2892");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-2893");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-2895");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-2896");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-2897");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-2898");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-2901");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-2903");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-2904");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-2921");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-2922");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-2923");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-2924");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-2925");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-2926");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-2928");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-2930");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-14539");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-14540");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-14547");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-14550");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-14553");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-14559");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-14567");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-14568");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-14575");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-14576");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-14586");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-14597");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-14614");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-14619");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-14620");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-14623");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-14624");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-14631");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-14632");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-14633");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-14634");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-14641");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-14643");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-14651");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-14654");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-14656");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-14663");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-14678");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-14680");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-14697");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-14702");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-14725");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-14799");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2021-1998");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2021-2006");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2021-2007");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2021-2009");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2021-2012");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2021-2016");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2021-2019");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2021-2020");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2021-2144");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2021-2160");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2020:3757");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1764675");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1764676");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1764680");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1764681");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1764684");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1764685");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1764686");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1764687");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1764688");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1764689");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1764691");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1764692");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1764693");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1764694");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1764695");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1764696");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1764698");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1764699");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1764700");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1764701");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1796880");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1796881");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1796882");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1796883");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1796884");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1796885");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1796886");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1796887");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1796888");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1796889");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1796905");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1798559");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1798576");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1798587");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1830048");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1830049");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1830050");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1830051");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1830052");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1830053");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1830054");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1830055");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1830056");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1830058");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1830059");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1830060");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1830061");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1830062");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1830064");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1830066");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1830067");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1830068");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1830069");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1830070");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1830071");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1830072");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1830073");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1830074");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1830075");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1830076");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1830077");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1830078");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1830079");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1830082");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1835849");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1835850");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1865945");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1865947");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1865948");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1865949");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1865950");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1865951");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1865952");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1865953");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1865954");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1865955");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1865956");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1865958");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1865959");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1865960");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1865961");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1865962");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1865963");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1865964");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1865965");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1865966");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1865967");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1865968");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1865969");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1865970");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1865971");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1865972");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1865973");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1865974");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1865975");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1865976");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1865977");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1865982");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1890752");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1922378");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1922381");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1922382");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1922386");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1922387");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1922420");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1922422");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1922424");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1951749");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1952806");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-14697");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2021-2144");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(400);

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/10/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/09/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/09/15");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:rhel_e4s:8.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:rhel_eus:8.1");
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

  script_copyright(english:"This script is Copyright (C) 2020-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (!rhel_check_release(operator: 'eq', os_version: os_ver, rhel_version: '8.1')) audit(AUDIT_OS_NOT, 'Red Hat 8.1', 'Red Hat ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu && 'ppc' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Red Hat', cpu);

var appstreams = {
  'mysql:8.0': [
    {
      'repo_relative_urls': [
        'content/e4s/rhel8/8.1/ppc64le/appstream/debug',
        'content/e4s/rhel8/8.1/ppc64le/appstream/os',
        'content/e4s/rhel8/8.1/ppc64le/appstream/source/SRPMS',
        'content/e4s/rhel8/8.1/ppc64le/baseos/debug',
        'content/e4s/rhel8/8.1/ppc64le/baseos/os',
        'content/e4s/rhel8/8.1/ppc64le/baseos/source/SRPMS',
        'content/e4s/rhel8/8.1/ppc64le/highavailability/debug',
        'content/e4s/rhel8/8.1/ppc64le/highavailability/os',
        'content/e4s/rhel8/8.1/ppc64le/highavailability/source/SRPMS',
        'content/e4s/rhel8/8.1/ppc64le/sap-solutions/debug',
        'content/e4s/rhel8/8.1/ppc64le/sap-solutions/os',
        'content/e4s/rhel8/8.1/ppc64le/sap-solutions/source/SRPMS',
        'content/e4s/rhel8/8.1/ppc64le/sap/debug',
        'content/e4s/rhel8/8.1/ppc64le/sap/os',
        'content/e4s/rhel8/8.1/ppc64le/sap/source/SRPMS',
        'content/e4s/rhel8/8.1/x86_64/appstream/debug',
        'content/e4s/rhel8/8.1/x86_64/appstream/os',
        'content/e4s/rhel8/8.1/x86_64/appstream/source/SRPMS',
        'content/e4s/rhel8/8.1/x86_64/baseos/debug',
        'content/e4s/rhel8/8.1/x86_64/baseos/os',
        'content/e4s/rhel8/8.1/x86_64/baseos/source/SRPMS',
        'content/e4s/rhel8/8.1/x86_64/highavailability/debug',
        'content/e4s/rhel8/8.1/x86_64/highavailability/os',
        'content/e4s/rhel8/8.1/x86_64/highavailability/source/SRPMS',
        'content/e4s/rhel8/8.1/x86_64/sap-solutions/debug',
        'content/e4s/rhel8/8.1/x86_64/sap-solutions/os',
        'content/e4s/rhel8/8.1/x86_64/sap-solutions/source/SRPMS',
        'content/e4s/rhel8/8.1/x86_64/sap/debug',
        'content/e4s/rhel8/8.1/x86_64/sap/os',
        'content/e4s/rhel8/8.1/x86_64/sap/source/SRPMS',
        'content/eus/rhel8/8.1/aarch64/appstream/debug',
        'content/eus/rhel8/8.1/aarch64/appstream/os',
        'content/eus/rhel8/8.1/aarch64/appstream/source/SRPMS',
        'content/eus/rhel8/8.1/aarch64/baseos/debug',
        'content/eus/rhel8/8.1/aarch64/baseos/os',
        'content/eus/rhel8/8.1/aarch64/baseos/source/SRPMS',
        'content/eus/rhel8/8.1/aarch64/codeready-builder/debug',
        'content/eus/rhel8/8.1/aarch64/codeready-builder/os',
        'content/eus/rhel8/8.1/aarch64/codeready-builder/source/SRPMS',
        'content/eus/rhel8/8.1/aarch64/highavailability/debug',
        'content/eus/rhel8/8.1/aarch64/highavailability/os',
        'content/eus/rhel8/8.1/aarch64/highavailability/source/SRPMS',
        'content/eus/rhel8/8.1/aarch64/supplementary/debug',
        'content/eus/rhel8/8.1/aarch64/supplementary/os',
        'content/eus/rhel8/8.1/aarch64/supplementary/source/SRPMS',
        'content/eus/rhel8/8.1/ppc64le/appstream/debug',
        'content/eus/rhel8/8.1/ppc64le/appstream/os',
        'content/eus/rhel8/8.1/ppc64le/appstream/source/SRPMS',
        'content/eus/rhel8/8.1/ppc64le/baseos/debug',
        'content/eus/rhel8/8.1/ppc64le/baseos/os',
        'content/eus/rhel8/8.1/ppc64le/baseos/source/SRPMS',
        'content/eus/rhel8/8.1/ppc64le/codeready-builder/debug',
        'content/eus/rhel8/8.1/ppc64le/codeready-builder/os',
        'content/eus/rhel8/8.1/ppc64le/codeready-builder/source/SRPMS',
        'content/eus/rhel8/8.1/ppc64le/highavailability/debug',
        'content/eus/rhel8/8.1/ppc64le/highavailability/os',
        'content/eus/rhel8/8.1/ppc64le/highavailability/source/SRPMS',
        'content/eus/rhel8/8.1/ppc64le/resilientstorage/debug',
        'content/eus/rhel8/8.1/ppc64le/resilientstorage/os',
        'content/eus/rhel8/8.1/ppc64le/resilientstorage/source/SRPMS',
        'content/eus/rhel8/8.1/ppc64le/sap-solutions/debug',
        'content/eus/rhel8/8.1/ppc64le/sap-solutions/os',
        'content/eus/rhel8/8.1/ppc64le/sap-solutions/source/SRPMS',
        'content/eus/rhel8/8.1/ppc64le/sap/debug',
        'content/eus/rhel8/8.1/ppc64le/sap/os',
        'content/eus/rhel8/8.1/ppc64le/sap/source/SRPMS',
        'content/eus/rhel8/8.1/ppc64le/supplementary/debug',
        'content/eus/rhel8/8.1/ppc64le/supplementary/os',
        'content/eus/rhel8/8.1/ppc64le/supplementary/source/SRPMS',
        'content/eus/rhel8/8.1/s390x/appstream/debug',
        'content/eus/rhel8/8.1/s390x/appstream/os',
        'content/eus/rhel8/8.1/s390x/appstream/source/SRPMS',
        'content/eus/rhel8/8.1/s390x/baseos/debug',
        'content/eus/rhel8/8.1/s390x/baseos/os',
        'content/eus/rhel8/8.1/s390x/baseos/source/SRPMS',
        'content/eus/rhel8/8.1/s390x/codeready-builder/debug',
        'content/eus/rhel8/8.1/s390x/codeready-builder/os',
        'content/eus/rhel8/8.1/s390x/codeready-builder/source/SRPMS',
        'content/eus/rhel8/8.1/s390x/highavailability/debug',
        'content/eus/rhel8/8.1/s390x/highavailability/os',
        'content/eus/rhel8/8.1/s390x/highavailability/source/SRPMS',
        'content/eus/rhel8/8.1/s390x/resilientstorage/debug',
        'content/eus/rhel8/8.1/s390x/resilientstorage/os',
        'content/eus/rhel8/8.1/s390x/resilientstorage/source/SRPMS',
        'content/eus/rhel8/8.1/s390x/sap/debug',
        'content/eus/rhel8/8.1/s390x/sap/os',
        'content/eus/rhel8/8.1/s390x/sap/source/SRPMS',
        'content/eus/rhel8/8.1/s390x/supplementary/debug',
        'content/eus/rhel8/8.1/s390x/supplementary/os',
        'content/eus/rhel8/8.1/s390x/supplementary/source/SRPMS',
        'content/eus/rhel8/8.1/x86_64/appstream/debug',
        'content/eus/rhel8/8.1/x86_64/appstream/os',
        'content/eus/rhel8/8.1/x86_64/appstream/source/SRPMS',
        'content/eus/rhel8/8.1/x86_64/baseos/debug',
        'content/eus/rhel8/8.1/x86_64/baseos/os',
        'content/eus/rhel8/8.1/x86_64/baseos/source/SRPMS',
        'content/eus/rhel8/8.1/x86_64/codeready-builder/debug',
        'content/eus/rhel8/8.1/x86_64/codeready-builder/os',
        'content/eus/rhel8/8.1/x86_64/codeready-builder/source/SRPMS',
        'content/eus/rhel8/8.1/x86_64/highavailability/debug',
        'content/eus/rhel8/8.1/x86_64/highavailability/os',
        'content/eus/rhel8/8.1/x86_64/highavailability/source/SRPMS',
        'content/eus/rhel8/8.1/x86_64/resilientstorage/debug',
        'content/eus/rhel8/8.1/x86_64/resilientstorage/os',
        'content/eus/rhel8/8.1/x86_64/resilientstorage/source/SRPMS',
        'content/eus/rhel8/8.1/x86_64/sap-solutions/debug',
        'content/eus/rhel8/8.1/x86_64/sap-solutions/os',
        'content/eus/rhel8/8.1/x86_64/sap-solutions/source/SRPMS',
        'content/eus/rhel8/8.1/x86_64/sap/debug',
        'content/eus/rhel8/8.1/x86_64/sap/os',
        'content/eus/rhel8/8.1/x86_64/sap/source/SRPMS',
        'content/eus/rhel8/8.1/x86_64/supplementary/debug',
        'content/eus/rhel8/8.1/x86_64/supplementary/os',
        'content/eus/rhel8/8.1/x86_64/supplementary/source/SRPMS'
      ],
      'pkgs': [
        {'reference':'mecab-0.996-1.module+el8.0.0+3898+e09bb8de.9', 'sp':'1', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'mecab-ipadic-2.7.0.20070801-16.module+el8.0.0+3898+e09bb8de', 'sp':'1', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'mecab-ipadic-EUCJP-2.7.0.20070801-16.module+el8.0.0+3898+e09bb8de', 'sp':'1', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'mysql-8.0.21-1.module+el8.1.0+7854+62e1520f', 'sp':'1', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'mysql-common-8.0.21-1.module+el8.1.0+7854+62e1520f', 'sp':'1', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'mysql-devel-8.0.21-1.module+el8.1.0+7854+62e1520f', 'sp':'1', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'mysql-errmsg-8.0.21-1.module+el8.1.0+7854+62e1520f', 'sp':'1', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'mysql-libs-8.0.21-1.module+el8.1.0+7854+62e1520f', 'sp':'1', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'mysql-server-8.0.21-1.module+el8.1.0+7854+62e1520f', 'sp':'1', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'mysql-test-8.0.21-1.module+el8.1.0+7854+62e1520f', 'sp':'1', 'release':'8', 'rpm_spec_vers_cmp':TRUE}
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
        if (!empty_or_null(package_array['sp'])) sp = package_array['sp'];
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
  var subscription_caveat = '\n' +
    'NOTE: This vulnerability check contains fixes that apply to\n' +
    'packages only available in the Red Hat Enterprise Linux\n' +
    'Extended Update Support or Update Services for SAP Solutions repositories.\n' +
    'Access to these repositories requires a paid RHEL subscription.\n';
  var extra = NULL;
  if (empty_or_null(applicable_repo_urls)) extra = subscription_caveat + rpm_report_get() + redhat_report_repo_caveat();
  else extra = subscription_caveat + rpm_report_get();
  security_report_v4(
      port       : 0,
      severity   : SECURITY_WARNING,
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
