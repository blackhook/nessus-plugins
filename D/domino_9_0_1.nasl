#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(71859);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/25");

  script_cve_id(
    "CVE-2012-1541",
    "CVE-2012-3213",
    "CVE-2012-3342",
    "CVE-2013-0351",
    "CVE-2013-0401",
    "CVE-2013-0402",
    "CVE-2013-0409",
    "CVE-2013-0419",
    "CVE-2013-0423",
    "CVE-2013-0424",
    "CVE-2013-0425",
    "CVE-2013-0426",
    "CVE-2013-0427",
    "CVE-2013-0428",
    "CVE-2013-0429",
    "CVE-2013-0430",
    "CVE-2013-0431",
    "CVE-2013-0432",
    "CVE-2013-0433",
    "CVE-2013-0434",
    "CVE-2013-0435",
    "CVE-2013-0437",
    "CVE-2013-0438",
    "CVE-2013-0440",
    "CVE-2013-0441",
    "CVE-2013-0442",
    "CVE-2013-0443",
    "CVE-2013-0444",
    "CVE-2013-0445",
    "CVE-2013-0446",
    "CVE-2013-0448",
    "CVE-2013-0449",
    "CVE-2013-0450",
    "CVE-2013-0809",
    "CVE-2013-1473",
    "CVE-2013-1475",
    "CVE-2013-1476",
    "CVE-2013-1478",
    "CVE-2013-1479",
    "CVE-2013-1480",
    "CVE-2013-1481",
    "CVE-2013-1488",
    "CVE-2013-1489",
    "CVE-2013-1491",
    "CVE-2013-1493",
    "CVE-2013-1500",
    "CVE-2013-1518",
    "CVE-2013-1537",
    "CVE-2013-1540",
    "CVE-2013-1557",
    "CVE-2013-1558",
    "CVE-2013-1561",
    "CVE-2013-1563",
    "CVE-2013-1564",
    "CVE-2013-1569",
    "CVE-2013-1571",
    "CVE-2013-2383",
    "CVE-2013-2384",
    "CVE-2013-2394",
    "CVE-2013-2400",
    "CVE-2013-2407",
    "CVE-2013-2412",
    "CVE-2013-2414",
    "CVE-2013-2415",
    "CVE-2013-2416",
    "CVE-2013-2417",
    "CVE-2013-2418",
    "CVE-2013-2419",
    "CVE-2013-2420",
    "CVE-2013-2421",
    "CVE-2013-2422",
    "CVE-2013-2423",
    "CVE-2013-2424",
    "CVE-2013-2425",
    "CVE-2013-2426",
    "CVE-2013-2427",
    "CVE-2013-2428",
    "CVE-2013-2429",
    "CVE-2013-2430",
    "CVE-2013-2431",
    "CVE-2013-2432",
    "CVE-2013-2433",
    "CVE-2013-2434",
    "CVE-2013-2435",
    "CVE-2013-2436",
    "CVE-2013-2437",
    "CVE-2013-2438",
    "CVE-2013-2439",
    "CVE-2013-2440",
    "CVE-2013-2442",
    "CVE-2013-2443",
    "CVE-2013-2444",
    "CVE-2013-2445",
    "CVE-2013-2446",
    "CVE-2013-2447",
    "CVE-2013-2448",
    "CVE-2013-2449",
    "CVE-2013-2450",
    "CVE-2013-2451",
    "CVE-2013-2452",
    "CVE-2013-2453",
    "CVE-2013-2454",
    "CVE-2013-2455",
    "CVE-2013-2456",
    "CVE-2013-2457",
    "CVE-2013-2458",
    "CVE-2013-2459",
    "CVE-2013-2460",
    "CVE-2013-2461",
    "CVE-2013-2462",
    "CVE-2013-2463",
    "CVE-2013-2464",
    "CVE-2013-2465",
    "CVE-2013-2466",
    "CVE-2013-2467",
    "CVE-2013-2468",
    "CVE-2013-2469",
    "CVE-2013-2470",
    "CVE-2013-2471",
    "CVE-2013-2472",
    "CVE-2013-2473",
    "CVE-2013-3006",
    "CVE-2013-3007",
    "CVE-2013-3008",
    "CVE-2013-3009",
    "CVE-2013-3010",
    "CVE-2013-3011",
    "CVE-2013-3012",
    "CVE-2013-3743",
    "CVE-2013-3744",
    "CVE-2013-4002",
    "CVE-2013-4063",
    "CVE-2013-4064",
    "CVE-2013-4065"
  );
  script_bugtraq_id(
    57681,
    57686,
    57687,
    57689,
    57691,
    57692,
    57694,
    57696,
    57697,
    57699,
    57700,
    57701,
    57702,
    57703,
    57704,
    57706,
    57707,
    57708,
    57709,
    57710,
    57711,
    57712,
    57713,
    57714,
    57715,
    57716,
    57717,
    57718,
    57719,
    57720,
    57722,
    57723,
    57724,
    57726,
    57727,
    57728,
    57729,
    57730,
    57731,
    58238,
    58296,
    58397,
    58493,
    58504,
    58507,
    59088,
    59089,
    59124,
    59128,
    59131,
    59137,
    59141,
    59145,
    59149,
    59153,
    59154,
    59159,
    59162,
    59165,
    59166,
    59167,
    59170,
    59172,
    59175,
    59178,
    59179,
    59184,
    59185,
    59187,
    59190,
    59191,
    59194,
    59195,
    59203,
    59206,
    59208,
    59212,
    59213,
    59219,
    59220,
    59228,
    59234,
    59243,
    60617,
    60618,
    60619,
    60620,
    60621,
    60622,
    60623,
    60624,
    60625,
    60626,
    60627,
    60629,
    60630,
    60631,
    60632,
    60633,
    60634,
    60635,
    60636,
    60637,
    60638,
    60639,
    60640,
    60641,
    60643,
    60644,
    60645,
    60646,
    60647,
    60649,
    60650,
    60651,
    60652,
    60653,
    60654,
    60655,
    60656,
    60657,
    60658,
    60659,
    61302,
    61306,
    61307,
    61308,
    61310,
    61311,
    61312,
    61313,
    64444,
    64445,
    64451
  );
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/04/18");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/06/15");

  script_name(english:"IBM Domino 9.x < 9.0.1 Multiple Vulnerabilities (uncredentialed check)");

  script_set_attribute(attribute:"synopsis", value:
"The remote server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its banner, the version of IBM Domino (formerly IBM Lotus
Domino) on the remote host is 9.x earlier than 9.0.1.  It is, therefore,
affected by the following vulnerabilities :

  - The included version of the IBM Java SDK contains a
    version of IBM JRE that contains numerous security
    issues. (CVE-2013-0809, CVE-2013-1493, CVE-2013-2436,
    CVE-2013-2455, CVE-2013-3006, CVE-2013-3007,
    CVE-2013-3008, CVE-2013-3009, CVE-2013-3010,
    CVE-2013-3011, CVE-2013-3012)

  - An input validation error exists related to handling
    content in email messages that could allow cross-site
    scripting attacks. (CVE-2013-4063)

  - An input validation error exists related to iNotes when
    running in 'ultra-light' mode that could allow cross-
    site scripting attacks. (CVE-2013-4064)

  - An input validation error exists related to handling
    content in email messages and iNotes when running in
    'ultra-light' mode that could allow cross-site
    scripting attacks. (CVE-2013-4065)

  - Note that fixes in the Oracle Java CPUs for February,
    April and June 2013 are included in the fixed IBM Java
    release, which is included in the fixed IBM Domino
    release. (CVE-2012-1541, CVE-2012-3213, CVE-2012-3342,
    CVE-2013-0351, CVE-2013-0401, CVE-2013-0402,
    CVE-2013-0409, CVE-2013-0419, CVE-2013-0423,
    CVE-2013-0424, CVE-2013-0425, CVE-2013-0426,
    CVE-2013-0427, CVE-2013-0428, CVE-2013-0429,
    CVE-2013-0430, CVE-2013-0431, CVE-2013-0432,
    CVE-2013-0433, CVE-2013-0434, CVE-2013-0435,
    CVE-2013-0437, CVE-2013-0438, CVE-2013-0440,
    CVE-2013-0441, CVE-2013-0442, CVE-2013-0443,
    CVE-2013-0444, CVE-2013-0445, CVE-2013-0446,
    CVE-2013-0448, CVE-2013-0449, CVE-2013-0450,
    CVE-2013-1473, CVE-2013-1475, CVE-2013-1476,
    CVE-2013-1478, CVE-2013-1479, CVE-2013-1480,
    CVE-2013-1481, CVE-2013-1488, CVE-2013-1489,
    CVE-2013-1491, CVE-2013-1500, CVE-2013-1518,
    CVE-2013-1537, CVE-2013-1540, CVE-2013-1557,
    CVE-2013-1558, CVE-2013-1561, CVE-2013-1563,
    CVE-2013-1564, CVE-2013-1569, CVE-2013-1571,
    CVE-2013-2383, CVE-2013-2384, CVE-2013-2394,
    CVE-2013-2400, CVE-2013-2407, CVE-2013-2412,
    CVE-2013-2414, CVE-2013-2415, CVE-2013-2416,
    CVE-2013-2417, CVE-2013-2418, CVE-2013-2419,
    CVE-2013-2420, CVE-2013-2421, CVE-2013-2422,
    CVE-2013-2423, CVE-2013-2424, CVE-2013-2425,
    CVE-2013-2426, CVE-2013-2427, CVE-2013-2428,
    CVE-2013-2429, CVE-2013-2430, CVE-2013-2431,
    CVE-2013-2432, CVE-2013-2433, CVE-2013-2434,
    CVE-2013-2435, CVE-2013-2437, CVE-2013-2438,
    CVE-2013-2439, CVE-2013-2440, CVE-2013-2442,
    CVE-2013-2443, CVE-2013-2444, CVE-2013-2445,
    CVE-2013-2446, CVE-2013-2447, CVE-2013-2448,
    CVE-2013-2449, CVE-2013-2450, CVE-2013-2451,
    CVE-2013-2452, CVE-2013-2453, CVE-2013-2454,
    CVE-2013-2456, CVE-2013-2457, CVE-2013-2458,
    CVE-2013-2459, CVE-2013-2460, CVE-2013-2461,
    CVE-2013-2462, CVE-2013-2463, CVE-2013-2464,
    CVE-2013-2465, CVE-2013-2466, CVE-2013-2467,
    CVE-2013-2468, CVE-2013-2469, CVE-2013-2470,
    CVE-2013-2471, CVE-2013-2472, CVE-2013-2473,
    CVE-2013-3743, CVE-2013-3744, CVE-2013-4002)");
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg27010592#ver901");
  # http://www-10.lotus.com/ldd/fixlist.nsf/8d1c0550e6242b69852570c900549a74/de0329821264ceff85257c130056adda?OpenDocument
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?fabb9d8f");
  script_set_attribute(attribute:"see_also", value:"https://www-304.ibm.com/support/docview.wss?uid=swg21644918");
  script_set_attribute(attribute:"solution", value:
"Upgrade to IBM Domino 9.0.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2013-2473");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Java storeImageArray() Invalid Array Indexing Vulnerability');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:"CANVAS");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/02/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/10/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/01/08");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:lotus_domino");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2014-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("domino_installed.nasl");
  script_require_keys("Domino/Version");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

# Check the version of Domino installed.
ver = get_kb_item_or_exit("Domino/Version");

port = get_kb_item("Domino/Version_provided_by_port");
if (!port) port = 0;

# Check that version is granular enough
if (ver == "9") audit(AUDIT_VER_NOT_GRANULAR, "IBM Domino", port, ver);

# Check that version is 9.0.x
if (ver !~ "^9\.0($|[^0-9])") audit(AUDIT_NOT_LISTEN, "IBM Domino 9.0.x", port);

# Affected 9.x < 9.0.1
if (
  ver == "9.0"                    ||
  ver =~ "^9\.0\.0($|[^0-9])"
)
{
  set_kb_item(name:"www/"+port+"/XSS", value:TRUE);
  if (report_verbosity > 0)
  {
    report =
      '\n' +
      '\n  Installed version : ' + ver +
      '\n  Fixed version     : 9.0.1' +
      '\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
}
else audit(AUDIT_LISTEN_NOT_VULN, "IBM Domino", port, ver);
