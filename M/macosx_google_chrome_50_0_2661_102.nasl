#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(91129);
  script_version("1.17");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/25");

  script_cve_id(
    "CVE-2016-1096",
    "CVE-2016-1097",
    "CVE-2016-1098",
    "CVE-2016-1099",
    "CVE-2016-1100",
    "CVE-2016-1101",
    "CVE-2016-1102",
    "CVE-2016-1103",
    "CVE-2016-1104",
    "CVE-2016-1105",
    "CVE-2016-1106",
    "CVE-2016-1107",
    "CVE-2016-1108",
    "CVE-2016-1109",
    "CVE-2016-1110",
    "CVE-2016-1667",
    "CVE-2016-1668",
    "CVE-2016-1669",
    "CVE-2016-1670",
    "CVE-2016-4108",
    "CVE-2016-4109",
    "CVE-2016-4110",
    "CVE-2016-4111",
    "CVE-2016-4112",
    "CVE-2016-4113",
    "CVE-2016-4114",
    "CVE-2016-4115",
    "CVE-2016-4116",
    "CVE-2016-4117",
    "CVE-2016-4120",
    "CVE-2016-4121",
    "CVE-2016-4160",
    "CVE-2016-4161",
    "CVE-2016-4162",
    "CVE-2016-4163"
  );
  script_bugtraq_id(90505);
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/03/24");

  script_name(english:"Google Chrome < 50.0.2661.102 Multiple Vulnerabilities (Mac OS X)");

  script_set_attribute(attribute:"synopsis", value:
"A web browser installed on the remote Mac OS X host is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Google Chrome installed on the remote Mac OS X host is
prior to 50.0.2661.102. It is, therefore, affected by multiple
vulnerabilities :

  - A same-origin bypass vulnerability exists in DOM due to
    scripts being permitted run while a node is being
    adopted. A context-dependent attacker can exploit this
    to bypass the same-origin policy. (CVE-2016-1667)

  - A same-origin bypass vulnerability exists due to a flaw
    in the Blink V8 bindings. A context-dependent attacker
    can exploit this to bypass the same-origin policy.
    (CVE-2016-1668)

  - An overflow condition exists in V8 due to improper
    validation of user-supplied input. A context-dependent
    attacker can exploit this to cause a denial of service
    condition or the execution of arbitrary code.
    (CVE-2016-1669)

  - A race condition exists in the loader related to the use
    of ids. An attacker can exploit this to have an
    unspecified impact. (CVE-2016-1670)

  - Multiple type confusion errors exist in the bundled
    version of Adobe Flash that allow an attacker to execute
    arbitrary code. (CVE-2016-1105, CVE-2016-4117)

  - Multiple use-after-free errors exist in the bundled
    version of Adobe Flash that allow an attacker to execute
    arbitrary code. (CVE-2016-1097, CVE-2016-1106,
    CVE-2016-1107, CVE-2016-1108, CVE-2016-1109,
    CVE-2016-1110, CVE-2016-4108, CVE-2016-4110, 
    CVE-2016-4121)

  - A heap buffer overflow condition exists in the bundled
    version of Adobe Flash that allows an attacker to
    execute arbitrary code. (CVE-2016-1101)

  - An unspecified buffer overflow exists in the bundled
    version of Adobe Flash that allows an attacker to
    execute arbitrary code. (CVE-2016-1103)

  - Multiple memory corruption issues exist in the bundled
    version of Adobe Flash that allow an attacker to execute
    arbitrary code. (CVE-2016-1096, CVE-2016-1098,
    CVE-2016-1099, CVE-2016-1100, CVE-2016-1102,
    CVE-2016-1104, CVE-2016-4109, CVE-2016-4111,
    CVE-2016-4112, CVE-2016-4113, CVE-2016-4114,
    CVE-2016-4115, CVE-2016-4120, CVE-2016-4160,
    CVE-2016-4161, CVE-2016-4162, CVE-2016-4163)

  - A flaw exists in the bundled version of Adobe Flash when
    loading dynamic-link libraries. An attacker can exploit
    this, via a specially crafted .dll file, to execute
    arbitrary code. (CVE-2016-4116)");
  # http://googlechromereleases.blogspot.com/2016/05/stable-channel-update.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ddef1fa8");
  script_set_attribute(attribute:"see_also", value:"https://helpx.adobe.com/security/products/flash-player/apsb16-15.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Google Chrome version 50.0.2661.102 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2016-4117");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2016-4163");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Adobe Flash Player DeleteRangeTimelineOperation Type-Confusion');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/05/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/05/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/05/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:google:chrome");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2016-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("macosx_google_chrome_installed.nbin");
  script_require_keys("MacOSX/Google Chrome/Installed");

  exit(0);
}

include("google_chrome_version.inc");

get_kb_item_or_exit("MacOSX/Google Chrome/Installed");

google_chrome_check_version(fix:'50.0.2661.102', severity:SECURITY_HOLE);
