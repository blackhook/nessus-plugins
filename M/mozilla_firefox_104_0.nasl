#%NASL_MIN_LEVEL 80900
## 
# (C) Tenable, Inc.
#                                  
# The descriptive text and package checks in this plugin were
# extracted from Mozilla Foundation Security Advisory mfsa2022-33.
# The text itself is copyright (C) Mozilla Foundation.
##

include('compat.inc');

if (description)
{
  script_id(164344);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/01/02");

  script_cve_id(
    "CVE-2022-38472",
    "CVE-2022-38473",
    "CVE-2022-38474",
    "CVE-2022-38475",
    "CVE-2022-38477",
    "CVE-2022-38478"
  );
  script_xref(name:"IAVA", value:"2022-A-0339-S");

  script_name(english:"Mozilla Firefox < 104.0");

  script_set_attribute(attribute:"synopsis", value:
"A web browser installed on the remote Windows host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Firefox installed on the remote Windows host is prior to 104.0. It is, therefore, affected by multiple
vulnerabilities as referenced in the mfsa2022-33 advisory.

  - An attacker could have abused XSLT error handling to associate attacker-controlled content with another
    origin which was displayed in the address bar. This could have been used to fool the user into submitting
    data intended for the spoofed origin. (CVE-2022-38472)

  - A cross-origin iframe referencing an XSLT document would inherit the parent domain's permissions (such as
    microphone or camera access). (CVE-2022-38473)

  - A website that had permission to access the microphone could record audio without the audio notification
    being shown. This bug does not allow the attacker to bypass the permission prompt - it only affects the
    notification shown once permission has been granted.<br />This bug only affects Firefox for Android. Other
    operating systems are unaffected. (CVE-2022-38474)

  - An attacker could have written a value to the first element in a zero-length JavaScript array. Although
    the array was zero-length, the value was not written to an invalid memory address. (CVE-2022-38475)

  - Mozilla developer Nika Layzell and the Mozilla Fuzzing Team reported memory safety bugs present in Firefox
    103 and Firefox ESR 102.1. Some of these bugs showed evidence of memory corruption and we presume that
    with enough effort some of these could have been exploited to run arbitrary code. (CVE-2022-38477)

  - Members the Mozilla Fuzzing Team reported memory safety bugs present in Firefox 103, Firefox ESR 102.1,
    and Firefox ESR 91.12. Some of these bugs showed evidence of memory corruption and we presume that with
    enough effort some of these could have been exploited to run arbitrary code. (CVE-2022-38478)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2022-33/");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Mozilla Firefox version 104.0 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-38478");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/08/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/08/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/08/23");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mozilla:firefox");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("mozilla_org_installed.nasl");
  script_require_keys("Mozilla/Firefox/Version");

  exit(0);
}

include('mozilla_version.inc');

var port = get_kb_item('SMB/transport');
if (!port) port = 445;

var installs = get_kb_list('SMB/Mozilla/Firefox/*');
if (isnull(installs)) audit(AUDIT_NOT_INST, 'Firefox');

mozilla_check_version(installs:installs, product:'firefox', esr:FALSE, fix:'104.0', severity:SECURITY_HOLE);
