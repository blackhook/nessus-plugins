#%NASL_MIN_LEVEL 70300
## 
# (C) Tenable Network Security, Inc.
#                                  
# The descriptive text and package checks in this plugin were
# extracted from Mozilla Foundation Security Advisory mfsa2021-20.
# The text itself is copyright (C) Mozilla Foundation.
##

include('deprecated_nasl_level.inc');

include('compat.inc');

if (description)
{
  script_id(149281);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/06/28");

  script_cve_id("CVE-2021-29952", "CVE-2021-29953");
  script_xref(name:"IAVA", value:"2021-A-0214-S");

  script_name(english:"Mozilla Firefox < 88.0.1");

  script_set_attribute(attribute:"synopsis", value:
"A web browser installed on the remote Windows host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Firefox installed on the remote Windows host is prior to 88.0.1. It is, therefore, affected by multiple
vulnerabilities as referenced in the mfsa2021-20 advisory.

  - A malicious webpage could have forced a Firefox for Android user into executing attacker-controlled
    JavaScript in the context of another domain, resulting in a Universal Cross-Site Scripting
    vulnerability.Note: This issue only affected Firefox for Android. Other operating systems are
    unaffected. Further details are being temporarily withheld to allow users an opportunity to update.
    (CVE-2021-29953)

  - When Web Render components were destructed, a race condition could have caused undefined behavior, and we
    presume that with enough effort may have been exploitable to run arbitrary code. (CVE-2021-29952)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2021-20/");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Mozilla Firefox version 88.0.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-29952");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/05/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/05/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/05/05");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mozilla:firefox");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("mozilla_org_installed.nasl");
  script_require_keys("Mozilla/Firefox/Version");

  exit(0);
}

include('mozilla_version.inc');

port = get_kb_item('SMB/transport');
if (!port) port = 445;

installs = get_kb_list('SMB/Mozilla/Firefox/*');
if (isnull(installs)) audit(AUDIT_NOT_INST, 'Firefox');

mozilla_check_version(installs:installs, product:'firefox', esr:FALSE, fix:'88.0.1', severity:SECURITY_WARNING);
