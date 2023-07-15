#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2013:1456. The text 
# itself is copyright (C) Red Hat, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(78976);
  script_version("1.22");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/05");

  script_cve_id(
    "CVE-2012-0547",
    "CVE-2012-0551",
    "CVE-2012-1531",
    "CVE-2012-1532",
    "CVE-2012-1533",
    "CVE-2012-1541",
    "CVE-2012-1682",
    "CVE-2012-1713",
    "CVE-2012-1716",
    "CVE-2012-1717",
    "CVE-2012-1718",
    "CVE-2012-1719",
    "CVE-2012-1721",
    "CVE-2012-1722",
    "CVE-2012-1725",
    "CVE-2012-3143",
    "CVE-2012-3159",
    "CVE-2012-3213",
    "CVE-2012-3216",
    "CVE-2012-3342",
    "CVE-2012-4820",
    "CVE-2012-4822",
    "CVE-2012-4823",
    "CVE-2012-5068",
    "CVE-2012-5069",
    "CVE-2012-5071",
    "CVE-2012-5072",
    "CVE-2012-5073",
    "CVE-2012-5075",
    "CVE-2012-5079",
    "CVE-2012-5081",
    "CVE-2012-5083",
    "CVE-2012-5084",
    "CVE-2012-5089",
    "CVE-2013-0169",
    "CVE-2013-0351",
    "CVE-2013-0401",
    "CVE-2013-0409",
    "CVE-2013-0419",
    "CVE-2013-0423",
    "CVE-2013-0424",
    "CVE-2013-0425",
    "CVE-2013-0426",
    "CVE-2013-0427",
    "CVE-2013-0428",
    "CVE-2013-0432",
    "CVE-2013-0433",
    "CVE-2013-0434",
    "CVE-2013-0435",
    "CVE-2013-0438",
    "CVE-2013-0440",
    "CVE-2013-0441",
    "CVE-2013-0442",
    "CVE-2013-0443",
    "CVE-2013-0445",
    "CVE-2013-0446",
    "CVE-2013-0450",
    "CVE-2013-0809",
    "CVE-2013-1473",
    "CVE-2013-1476",
    "CVE-2013-1478",
    "CVE-2013-1480",
    "CVE-2013-1481",
    "CVE-2013-1486",
    "CVE-2013-1487",
    "CVE-2013-1491",
    "CVE-2013-1493",
    "CVE-2013-1500",
    "CVE-2013-1537",
    "CVE-2013-1540",
    "CVE-2013-1557",
    "CVE-2013-1563",
    "CVE-2013-1569",
    "CVE-2013-1571",
    "CVE-2013-2383",
    "CVE-2013-2384",
    "CVE-2013-2394",
    "CVE-2013-2407",
    "CVE-2013-2412",
    "CVE-2013-2417",
    "CVE-2013-2418",
    "CVE-2013-2419",
    "CVE-2013-2420",
    "CVE-2013-2422",
    "CVE-2013-2424",
    "CVE-2013-2429",
    "CVE-2013-2430",
    "CVE-2013-2432",
    "CVE-2013-2433",
    "CVE-2013-2435",
    "CVE-2013-2437",
    "CVE-2013-2440",
    "CVE-2013-2442",
    "CVE-2013-2443",
    "CVE-2013-2444",
    "CVE-2013-2446",
    "CVE-2013-2447",
    "CVE-2013-2448",
    "CVE-2013-2450",
    "CVE-2013-2451",
    "CVE-2013-2452",
    "CVE-2013-2453",
    "CVE-2013-2454",
    "CVE-2013-2455",
    "CVE-2013-2456",
    "CVE-2013-2457",
    "CVE-2013-2459",
    "CVE-2013-2463",
    "CVE-2013-2464",
    "CVE-2013-2465",
    "CVE-2013-2466",
    "CVE-2013-2468",
    "CVE-2013-2469",
    "CVE-2013-2470",
    "CVE-2013-2471",
    "CVE-2013-2472",
    "CVE-2013-2473",
    "CVE-2013-3743"
  );
  script_xref(name:"RHSA", value:"2013:1456");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/04/18");
  script_xref(name:"CEA-ID", value:"CEA-2019-0547");

  script_name(english:"RHEL 5 / 6 : IBM Java Runtime in Satellite Server (RHSA-2013:1456) (ROBOT)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Red Hat host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"Updated java-1.6.0-ibm packages that fix several security issues are
now available for Red Hat Network Satellite Server 5.5.

The Red Hat Security Response Team has rated this update as having low
security impact. Common Vulnerability Scoring System (CVSS) base
scores, which give detailed severity ratings, are available for each
vulnerability from the CVE links in the References section.

This update corrects several security vulnerabilities in the IBM Java
Runtime Environment shipped as part of Red Hat Network Satellite
Server 5.5. In a typical operating environment, these are of low
security risk as the runtime is not used on untrusted applets.

Several flaws were fixed in the IBM Java 2 Runtime Environment.
(CVE-2012-0547, CVE-2012-0551, CVE-2012-1531, CVE-2012-1532,
CVE-2012-1533, CVE-2012-1541, CVE-2012-1682, CVE-2012-1713,
CVE-2012-1716, CVE-2012-1717, CVE-2012-1718, CVE-2012-1719,
CVE-2012-1721, CVE-2012-1722, CVE-2012-1725, CVE-2012-3143,
CVE-2012-3159, CVE-2012-3213, CVE-2012-3216, CVE-2012-3342,
CVE-2012-4820, CVE-2012-4822, CVE-2012-4823, CVE-2012-5068,
CVE-2012-5069, CVE-2012-5071, CVE-2012-5072, CVE-2012-5073,
CVE-2012-5075, CVE-2012-5079, CVE-2012-5081, CVE-2012-5083,
CVE-2012-5084, CVE-2012-5089, CVE-2013-0169, CVE-2013-0351,
CVE-2013-0401, CVE-2013-0409, CVE-2013-0419, CVE-2013-0423,
CVE-2013-0424, CVE-2013-0425, CVE-2013-0426, CVE-2013-0427,
CVE-2013-0428, CVE-2013-0432, CVE-2013-0433, CVE-2013-0434,
CVE-2013-0435, CVE-2013-0438, CVE-2013-0440, CVE-2013-0441,
CVE-2013-0442, CVE-2013-0443, CVE-2013-0445, CVE-2013-0446,
CVE-2013-0450, CVE-2013-0809, CVE-2013-1473, CVE-2013-1476,
CVE-2013-1478, CVE-2013-1480, CVE-2013-1481, CVE-2013-1486,
CVE-2013-1487, CVE-2013-1491, CVE-2013-1493, CVE-2013-1500,
CVE-2013-1537, CVE-2013-1540, CVE-2013-1557, CVE-2013-1563,
CVE-2013-1569, CVE-2013-1571, CVE-2013-2383, CVE-2013-2384,
CVE-2013-2394, CVE-2013-2407, CVE-2013-2412, CVE-2013-2417,
CVE-2013-2418, CVE-2013-2419, CVE-2013-2420, CVE-2013-2422,
CVE-2013-2424, CVE-2013-2429, CVE-2013-2430, CVE-2013-2432,
CVE-2013-2433, CVE-2013-2435, CVE-2013-2437, CVE-2013-2440,
CVE-2013-2442, CVE-2013-2443, CVE-2013-2444, CVE-2013-2446,
CVE-2013-2447, CVE-2013-2448, CVE-2013-2450, CVE-2013-2451,
CVE-2013-2452, CVE-2013-2453, CVE-2013-2454, CVE-2013-2455,
CVE-2013-2456, CVE-2013-2457, CVE-2013-2459, CVE-2013-2463,
CVE-2013-2464, CVE-2013-2465, CVE-2013-2466, CVE-2013-2468,
CVE-2013-2469, CVE-2013-2470, CVE-2013-2471, CVE-2013-2472,
CVE-2013-2473, CVE-2013-3743)

Users of Red Hat Network Satellite Server 5.5 are advised to upgrade
to these updated packages, which contain the IBM Java SE 6 SR14
release. For this update to take effect, Red Hat Network Satellite
Server must be restarted ('/usr/sbin/rhn-satellite restart'), as well
as all running instances of IBM Java.");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2013:1456");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2012-1725");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2012-1719");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2012-1718");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2012-1717");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2012-1716");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2012-1713");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2012-1722");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2012-0551");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2012-1721");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2012-0547");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2012-1682");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2012-5084");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2012-5079");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2012-5081");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2012-5069");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2012-5068");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2012-3216");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2012-5071");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2012-5072");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2012-5073");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2012-5089");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2012-5075");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2012-3159");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2012-3143");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2012-1531");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2012-1533");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2012-1532");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2012-5083");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2012-4820");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2012-4822");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2012-4823");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2013-1478");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2013-0450");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2013-1473");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2013-1476");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2012-1541");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2013-0409");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2013-1480");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2013-1481");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2013-0427");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2013-0426");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2013-0425");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2013-0424");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2013-0423");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2012-3213");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2013-0419");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2013-0445");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2013-0446");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2013-0441");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2013-0440");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2013-0443");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2013-0442");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2013-0351");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2012-3342");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2013-0432");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2013-0433");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2013-0434");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2013-0435");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2013-0438");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2013-0428");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2013-0169");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2013-1486");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2013-1487");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2013-1493");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2013-0809");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2013-2418");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2013-2394");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2013-2432");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2013-2433");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2013-2435");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2013-1540");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2013-1563");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2013-2419");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2013-1537");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2013-2417");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2013-2430");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2013-0401");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2013-1569");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2013-2383");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2013-2384");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2013-2420");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2013-2422");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2013-2424");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2013-2429");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2013-1557");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2013-2440");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2013-1491");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2013-2465");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2013-1571");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2013-2472");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2013-2412");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2013-2454");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2013-2455");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2013-2456");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2013-2457");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2013-2450");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2013-2452");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2013-2453");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2013-2459");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2013-2470");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2013-2471");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2013-2473");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2013-2447");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2013-2446");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2013-2463");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2013-2407");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2013-1500");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2013-2448");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2013-2469");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2013-2443");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2013-2444");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2013-2451");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2013-2464");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2013-2468");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2013-2442");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2013-2466");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2013-2437");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2013-3743");
  script_set_attribute(attribute:"solution", value:
"Update the affected java-1.6.0-ibm and / or java-1.6.0-ibm-devel
packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2013-2473");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Java storeImageArray() Invalid Array Indexing Vulnerability');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"in_the_news", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/05/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/10/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/11/08");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:java-1.6.0-ibm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:java-1.6.0-ibm-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Red Hat Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2014-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/RedHat/release", "Host/RedHat/rpm-list", "Host/cpu");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || "Red Hat" >!< release) audit(AUDIT_OS_NOT, "Red Hat");
os_ver = pregmatch(pattern: "Red Hat Enterprise Linux.*release ([0-9]+(\.[0-9]+)?)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Red Hat");
os_ver = os_ver[1];
if (! preg(pattern:"^(5|6)([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 5.x / 6.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2013:1456";
  yum_report = redhat_generate_yum_updateinfo_report(rhsa:rhsa);
  if (!empty_or_null(yum_report))
  {
    security_report_v4(
      port       : 0,
      severity   : SECURITY_HOLE,
      extra      : yum_report 
    );
    exit(0);
  }
  else
  {
    audit_message = "affected by Red Hat security advisory " + rhsa;
    audit(AUDIT_OS_NOT, audit_message);
  }
}
else
{
  flag = 0;

  if (! (rpm_exists(release:"RHEL5", rpm:"spacewalk-admin-") || rpm_exists(release:"RHEL6", rpm:"spacewalk-admin-"))) audit(AUDIT_PACKAGE_NOT_INSTALLED, "Satellite Server");

  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"java-1.6.0-ibm-1.6.0.14.0-1jpp.1.el5_9")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"java-1.6.0-ibm-1.6.0.14.0-1jpp.1.el5_9")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"java-1.6.0-ibm-devel-1.6.0.14.0-1jpp.1.el5_9")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"java-1.6.0-ibm-devel-1.6.0.14.0-1jpp.1.el5_9")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"java-1.6.0-ibm-1.6.0.14.0-1jpp.1.el6_4")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"java-1.6.0-ibm-1.6.0.14.0-1jpp.1.el6_4")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"java-1.6.0-ibm-devel-1.6.0.14.0-1jpp.1.el6_4")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"java-1.6.0-ibm-devel-1.6.0.14.0-1jpp.1.el6_4")) flag++;

  if (flag)
  {
    security_report_v4(
      port       : 0,
      severity   : SECURITY_HOLE,
      extra      : rpm_report_get() + redhat_report_package_caveat()
    );
    exit(0);
  }
  else
  {
    tested = pkg_tests_get();
    if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "java-1.6.0-ibm / java-1.6.0-ibm-devel");
  }
}
