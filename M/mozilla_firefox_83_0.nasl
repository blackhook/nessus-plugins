## 
# (C) Tenable Network Security, Inc.
#                                  
# The descriptive text and package checks in this plugin were
# extracted from Mozilla Foundation Security Advisory mfsa2020-50.
# The text itself is copyright (C) Mozilla Foundation.
##

include('compat.inc');

if (description)
{
  script_id(142910);
  script_version("1.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/05");

  script_cve_id(
    "CVE-2020-15999",
    "CVE-2020-16012",
    "CVE-2020-26951",
    "CVE-2020-26952",
    "CVE-2020-26953",
    "CVE-2020-26954",
    "CVE-2020-26955",
    "CVE-2020-26956",
    "CVE-2020-26957",
    "CVE-2020-26958",
    "CVE-2020-26959",
    "CVE-2020-26960",
    "CVE-2020-26961",
    "CVE-2020-26962",
    "CVE-2020-26963",
    "CVE-2020-26964",
    "CVE-2020-26965",
    "CVE-2020-26966",
    "CVE-2020-26967",
    "CVE-2020-26968",
    "CVE-2020-26969"
  );
  script_xref(name:"MFSA", value:"2020-50");
  script_xref(name:"IAVA", value:"2020-A-0537-S");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2021/11/17");
  script_xref(name:"CEA-ID", value:"CEA-2020-0124");

  script_name(english:"Mozilla Firefox < 83.0");

  script_set_attribute(attribute:"synopsis", value:
"A web browser installed on the remote Windows host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Firefox installed on the remote Windows host is prior to 83.0. It is, therefore, affected by multiple
vulnerabilities as referenced in the mfsa2020-50 advisory, including the following:

  - Mozilla developers reported memory safety bugs present in Firefox 82. Some of these bugs showed evidence
    of memory corruption and we presume that with enough effort some of these could have been exploited to run
    arbitrary code. This vulnerability affects Firefox < 83. (CVE-2020-26969)

  - If the Compact() method was called on an nsTArray, the array could have been reallocated without updating
    other pointers, leading to a potential use-after-free and exploitable crash. This vulnerability affects
    Firefox < 83, Firefox ESR < 78.5, and Thunderbird < 78.5. (CVE-2020-26960)

  - Mozilla developers reported memory safety bugs present in Firefox 82 and Firefox ESR 78.4. Some of these
    bugs showed evidence of memory corruption and we presume that with enough effort some of these could have
    been exploited to run arbitrary code. This vulnerability affects Firefox < 83, Firefox ESR < 78.5, and
    Thunderbird < 78.5. (CVE-2020-26968)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2020-50/");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Mozilla Firefox version 83.0 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-26969");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/10/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/11/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/11/17");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mozilla:firefox");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2020-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("mozilla_org_installed.nasl");
  script_require_keys("Mozilla/Firefox/Version");

  exit(0);
}

include('mozilla_version.inc');

port = get_kb_item('SMB/transport');
if (!port) port = 445;

installs = get_kb_list('SMB/Mozilla/Firefox/*');
if (isnull(installs)) audit(AUDIT_NOT_INST, 'Firefox');

mozilla_check_version(installs:installs, product:'firefox', esr:FALSE, fix:'83.0', xss:TRUE, severity:SECURITY_HOLE);
