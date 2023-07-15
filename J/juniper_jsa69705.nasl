##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(163770);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/01/05");

  script_cve_id(
    "CVE-2020-9327",
    "CVE-2020-11655",
    "CVE-2020-11656",
    "CVE-2020-13434",
    "CVE-2020-13435",
    "CVE-2020-13630",
    "CVE-2020-13631",
    "CVE-2020-13632",
    "CVE-2020-13871",
    "CVE-2020-15358",
    "CVE-2021-20227",
    "CVE-2021-36690"
  );
  script_xref(name:"JSA", value:"JSA69705");
  script_xref(name:"IAVA", value:"2022-A-0382-S");
  script_xref(name:"CEA-ID", value:"CEA-2021-0004");
  script_xref(name:"CEA-ID", value:"CEA-2021-0025");

  script_name(english:"Juniper Junos OS Multiple Vulnerabilities (JSA69705)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The version of Junos OS installed on the remote host is affected by multiple vulnerabilities as referenced in the
JSA69705 advisory.

  - ** DISPUTED ** A segmentation fault can occur in the sqlite3.exe command-line component of SQLite 3.36.0
    via the idxGetTableInfo function when there is a crafted SQL query. NOTE: the vendor disputes the
    relevance of this report because a sqlite3.exe user already has full privileges (e.g., is intentionally
    allowed to execute commands). This report does NOT imply any problem in the SQLite library.
    (CVE-2021-36690)

  - A flaw was found in SQLite's SELECT query functionality (src/select.c). This flaw allows an attacker who
    is capable of running SQL queries locally on the SQLite database to cause a denial of service or possible
    code execution by triggering a use-after-free. The highest threat from this vulnerability is to system
    availability. (CVE-2021-20227)

  - In SQLite before 3.32.3, select.c mishandles query-flattener optimization, leading to a multiSelectOrderBy
    heap overflow because of misuse of transitive properties for constant propagation. (CVE-2020-15358)

  - SQLite 3.32.2 has a use-after-free in resetAccumulator in select.c because the parse tree rewrite for
    window functions is too late. (CVE-2020-13871)

  - ext/fts3/fts3_snippet.c in SQLite before 3.32.0 has a NULL pointer dereference via a crafted matchinfo()
    query. (CVE-2020-13632)

  - SQLite before 3.32.0 allows a virtual table to be renamed to the name of one of its shadow tables, related
    to alter.c and build.c. (CVE-2020-13631)

  - SQLite through 3.32.0 has a segmentation fault in sqlite3ExprCodeTarget in expr.c. (CVE-2020-13435)

  - SQLite through 3.32.0 has an integer overflow in sqlite3_str_vappendf in printf.c. (CVE-2020-13434)

  - SQLite through 3.31.1 allows attackers to cause a denial of service (segmentation fault) via a malformed
    window-function query because the AggInfo object's initialization is mishandled. (CVE-2020-11655)

  - In SQLite 3.31.1, isAuxiliaryVtabOperator allows attackers to trigger a NULL pointer dereference and
    segmentation fault because of generated column optimizations. (CVE-2020-9327)

  - In SQLite through 3.31.1, the ALTER TABLE implementation has a use-after-free, as demonstrated by an ORDER
    BY clause that belongs to a compound SELECT statement. (CVE-2020-11656)

  - ext/fts3/fts3.c in SQLite before 3.32.0 has a use-after-free in fts3EvalNextRow, related to the snippet
    feature. (CVE-2020-13630)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://supportportal.juniper.net/s/article/Overview-of-the-Juniper-Networks-SIRT-Quarterly-Security-Bulletin-Publication-Process
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?99086ea4");
  # https://supportportal.juniper.net/s/article/In-which-releases-are-vulnerabilities-fixed
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b616ed59");
  # https://supportportal.juniper.net/s/article/Common-Vulnerability-Scoring-System-CVSS-and-Juniper-s-Security-Advisories
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0d4fd08b");
  script_set_attribute(attribute:"see_also", value:"https://www.sqlite.org/cves.html");
  script_set_attribute(attribute:"see_also", value:"https://sqlite.org/releaselog/3_37_0.html");
  script_set_attribute(attribute:"see_also", value:"https://sqlite.org/releaselog/3_37_2.html");
  # https://supportportal.juniper.net/s/article/2022-07-Security-Bulletin-Junos-OS-and-Junos-OS-Evolved-Multiple-vulnerabilities-in-SQLite-resolved
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b453d5bb");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant Junos software release referenced in Juniper advisory JSA69705");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-11656");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/02/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/07/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/08/03");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:juniper:junos");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Junos Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("junos_version.nasl");
  script_require_keys("Host/Juniper/JUNOS/Version");

  exit(0);
}

include('junos.inc');


var ver = get_kb_item_or_exit('Host/Juniper/JUNOS/Version');

var vuln_ranges = [
  {'min_ver':'15.1X49', 'fixed_ver':'15.1X49-D100'},
  {'min_ver':'19.3', 'fixed_ver':'19.3R3-S6'},
  {'min_ver':'19.4', 'fixed_ver':'19.4R2-S6'},
  {'min_ver':'19.4R3', 'fixed_ver':'19.4R3-S8'},
  {'min_ver':'20.1', 'fixed_ver':'20.1R3-S4'},
  {'min_ver':'20.2', 'fixed_ver':'20.2R3-S4'},
  {'min_ver':'20.3', 'fixed_ver':'20.3R3-S3'},
  {'min_ver':'20.4', 'fixed_ver':'20.4R3-S3'},
  {'min_ver':'21.1', 'fixed_ver':'21.1R3-S1'},
  {'min_ver':'21.2', 'fixed_ver':'21.2R2-S2'},
  {'min_ver':'21.3', 'fixed_ver':'21.3R2', 'fixed_display':'21.3R2, 21.3R3-EVO'},
  {'min_ver':'21.4', 'fixed_ver':'21.4R1-S1', 'fixed_display':'21.4R1-S1, 21.4R2, 21.4R2-EVO'}
];

var fix = junos_compare_range(target_version:ver, vuln_ranges:vuln_ranges);
if (empty_or_null(fix)) audit(AUDIT_INST_VER_NOT_VULN, 'Junos OS', ver);
var report = get_report(ver:ver, fix:fix);
security_report_v4(severity:SECURITY_HOLE, port:0, extra:report);
