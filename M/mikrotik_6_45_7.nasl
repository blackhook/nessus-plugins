#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(130432);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/18");

  script_cve_id(
    "CVE-2019-3976",
    "CVE-2019-3977",
    "CVE-2019-3978",
    "CVE-2019-3979"
  );
  script_xref(name:"TRA", value:"TRA-2019-46");

  script_name(english:"MikroTik RouterOS < 6.44.6 LTS or 6.45.x < 6.45.7 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The remote networking device is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the remote networking device is
running a version of MikroTik RouterOS prior to 6.44.6 LTS or 6.45.x prior to
6.45.7. It is, therefore, affected by multiple vulnerabilities :

  - Relative Path Traversal in NPK Parsing - RouterOS 6.45.6 Stable, RouterOS
  6.44.5 Long-term, and below are vulnerable to an arbitrary directory creation
  vulnerability via the upgrade package's name field. If an authenticated user
  installs a malicious package then a directory could be created and the
  developer shell could be enabled. (CVE-2019-3976)

  - RouterOS 6.45.6 Stable, RouterOS 6.44.5 Long-term, and below insufficiently
  validate where upgrade packages are download from when using the autoupgrade
  feature. Therefore, a remote attacker can trick the router into 'upgrading'
  to an older version of RouterOS and possibly resetting all the system's
  usernames and passwords. (CVE-2019-3977)

  - Insufficient Protections of a Critical Resource (DNS Requests/Cache) -
  RouterOS versions 6.45.6 Stable, 6.44.5 Long-term, and below allow remote
  unauthenticated attackers to trigger DNS queries via port 8291. The queries
  are sent from the router to a server of the attacker's choice. The DNS
  responses are cached by the router, potentially resulting in cache poisoning.

  - Improper DNS Response Handling - RouterOS versions 6.45.6 Stable, 6.44.5
  Long-term, and below are vulnerable to a DNS unrelated data attack. The
  router adds all A records to its DNS cache even when the records are
  unrelated to the domain that was queried. Therefore, a remote attacker
  controlled DNS server can poison the router's DNS cache via malicious
  responses with additional and untrue records.

Note that Nessus has not tested for this issue but has instead relied only on
the routers's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"https://www.tenable.com/security/research/tra-2019-46");
  script_set_attribute(attribute:"see_also", value:"https://forum.mikrotik.com/viewtopic.php?f=21&t=153378");
  script_set_attribute(attribute:"see_also", value:"https://forum.mikrotik.com/viewtopic.php?f=21&t=153379");
  script_set_attribute(attribute:"solution", value:
"Upgrade to MikroTik RouterOS 6.44.6 LTS, 6.45.7 and later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:C/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-3977");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2019-3976");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"in_the_news", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/10/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/10/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/10/31");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mikrotik:routeros");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2019-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("mikrotik_detect.nasl", "ssh_detect.nasl");
  script_require_keys("MikroTik/RouterOS/Version");

  exit(0);
}

include('vcf.inc');

app = 'MikroTik';
kb_ver = 'MikroTik/RouterOS/Version';

app_info = vcf::get_app_info(app:app, kb_ver:kb_ver);

constraints = [{ 'fixed_version' : '6.44.6' },
               { 'min_version' : '6.45', 'fixed_version' : '6.45.7' }];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE, strict:FALSE);
