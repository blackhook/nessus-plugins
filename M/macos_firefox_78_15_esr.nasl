#%NASL_MIN_LEVEL 70300
## 
# (C) Tenable Network Security, Inc.
#                                  
# The descriptive text and package checks in this plugin were
# extracted from Mozilla Foundation Security Advisory mfsa2021-44.
# The text itself is copyright (C) Mozilla Foundation.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(153876);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/01/26");

  script_cve_id("CVE-2021-38496", "CVE-2021-38500");
  script_xref(name:"IAVA", value:"2021-A-0461-S");
  script_xref(name:"IAVA", value:"2021-A-0450-S");

  script_name(english:"Mozilla Firefox ESR < 78.15");

  script_set_attribute(attribute:"synopsis", value:
"A web browser installed on the remote macOS or Mac OS X host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Firefox ESR installed on the remote macOS or Mac OS X host is prior to 78.15. It is, therefore, affected
by multiple vulnerabilities as referenced in the mfsa2021-44 advisory.

  - During operations on MessageTasks, a task may have been removed while it was still scheduled, resulting in
    memory corruption and a potentially exploitable crash. (CVE-2021-38496)

  - Mozilla developers and community members Andreas Pehrson and Christian Holler reported memory safety bugs
    present in Firefox 92 and Firefox ESR 91.1. Some of these bugs showed evidence of memory corruption and we
    presume that with enough effort some of these could have been exploited to run arbitrary code.
    (CVE-2021-38500)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2021-44/");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Mozilla Firefox ESR version 78.15 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-38500");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/10/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/10/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/10/05");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mozilla:firefox_esr");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("macosx_firefox_installed.nasl");
  script_require_keys("MacOSX/Firefox/Version");

  exit(0);
}

include('mozilla_version.inc');

var kb_base = 'MacOSX/Firefox';
get_kb_item_or_exit(kb_base+'/Installed');

var version = get_kb_item_or_exit(kb_base+'/Version', exit_code:1);
var path = get_kb_item_or_exit(kb_base+'/Path', exit_code:1);

var is_esr = get_kb_item(kb_base+'/is_esr');
if (isnull(is_esr)) audit(AUDIT_NOT_INST, 'Mozilla Firefox ESR');

mozilla_check_version(version:version, path:path, product:'firefox', esr:TRUE, fix:'78.15', min:'78.0.0', severity:SECURITY_WARNING);
