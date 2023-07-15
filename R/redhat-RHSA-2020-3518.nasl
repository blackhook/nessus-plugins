#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2020:3518. The text
# itself is copyright (C) Red Hat, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(170309);
  script_version("1.2");
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
  script_xref(name:"RHSA", value:"2020:3518");
  script_xref(name:"CEA-ID", value:"CEA-2021-0004");
  script_xref(name:"CEA-ID", value:"CEA-2021-0025");

  script_name(english:"RHEL 7 : rh-mysql80-mysql (RHSA-2020:3518)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Red Hat host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Redhat Enterprise Linux 7 host has packages installed that are affected by multiple vulnerabilities as
referenced in the RHSA-2020:3518 advisory.

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
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2020:3518");
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
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-2144");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(400);

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/10/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/08/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/01/23");

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
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Red Hat Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
      {'reference':'rh-mysql80-mysql-8.0.21-1.el7', 'cpu':'ppc64le', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-mysql80-mysql-8.0.21-1.el7', 'cpu':'s390x', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-mysql80-mysql-8.0.21-1.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-mysql80-mysql-common-8.0.21-1.el7', 'cpu':'ppc64le', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-mysql80-mysql-common-8.0.21-1.el7', 'cpu':'s390x', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-mysql80-mysql-common-8.0.21-1.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-mysql80-mysql-config-8.0.21-1.el7', 'cpu':'ppc64le', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-mysql80-mysql-config-8.0.21-1.el7', 'cpu':'s390x', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-mysql80-mysql-config-8.0.21-1.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-mysql80-mysql-config-syspaths-8.0.21-1.el7', 'cpu':'ppc64le', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-mysql80-mysql-config-syspaths-8.0.21-1.el7', 'cpu':'s390x', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-mysql80-mysql-config-syspaths-8.0.21-1.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-mysql80-mysql-devel-8.0.21-1.el7', 'cpu':'ppc64le', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-mysql80-mysql-devel-8.0.21-1.el7', 'cpu':'s390x', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-mysql80-mysql-devel-8.0.21-1.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-mysql80-mysql-errmsg-8.0.21-1.el7', 'cpu':'ppc64le', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-mysql80-mysql-errmsg-8.0.21-1.el7', 'cpu':'s390x', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-mysql80-mysql-errmsg-8.0.21-1.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-mysql80-mysql-server-8.0.21-1.el7', 'cpu':'ppc64le', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-mysql80-mysql-server-8.0.21-1.el7', 'cpu':'s390x', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-mysql80-mysql-server-8.0.21-1.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-mysql80-mysql-server-syspaths-8.0.21-1.el7', 'cpu':'ppc64le', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-mysql80-mysql-server-syspaths-8.0.21-1.el7', 'cpu':'s390x', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-mysql80-mysql-server-syspaths-8.0.21-1.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-mysql80-mysql-syspaths-8.0.21-1.el7', 'cpu':'ppc64le', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-mysql80-mysql-syspaths-8.0.21-1.el7', 'cpu':'s390x', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-mysql80-mysql-syspaths-8.0.21-1.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-mysql80-mysql-test-8.0.21-1.el7', 'cpu':'ppc64le', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-mysql80-mysql-test-8.0.21-1.el7', 'cpu':'s390x', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-mysql80-mysql-test-8.0.21-1.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE}
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
      severity   : SECURITY_WARNING,
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
