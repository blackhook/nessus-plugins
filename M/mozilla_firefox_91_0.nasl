#%NASL_MIN_LEVEL 70300
## 
# (C) Tenable Network Security, Inc.
#                                  
# The descriptive text and package checks in this plugin were
# extracted from Mozilla Foundation Security Advisory mfsa2021-33.
# The text itself is copyright (C) Mozilla Foundation.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(152412);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/09/10");

  script_cve_id(
    "CVE-2021-29980",
    "CVE-2021-29981",
    "CVE-2021-29982",
    "CVE-2021-29983",
    "CVE-2021-29984",
    "CVE-2021-29985",
    "CVE-2021-29986",
    "CVE-2021-29987",
    "CVE-2021-29988",
    "CVE-2021-29989",
    "CVE-2021-29990"
  );
  script_xref(name:"IAVA", value:"2021-A-0366-S");

  script_name(english:"Mozilla Firefox < 91.0");

  script_set_attribute(attribute:"synopsis", value:
"A web browser installed on the remote Windows host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Firefox installed on the remote Windows host is prior to 91.0. It is, therefore, affected by multiple
vulnerabilities as referenced in the mfsa2021-33 advisory.

  - A suspected race condition when calling getaddrinfo led to memory corruption and a
    potentially exploitable crash. Note: This issue only affected Linux operating systems. Other operating
    systems are unaffected. (CVE-2021-29986)

  - An issue present in lowering/register allocation could have led to obscure but deterministic register
    confusion failures in JITted code that would lead to a potentially exploitable crash. (CVE-2021-29981)

  - Firefox incorrectly treated an inline list-item element as a block element, resulting in an out of bounds
    read or memory corruption, and a potentially exploitable crash. (CVE-2021-29988)

  - Firefox for Android could get stuck in fullscreen mode and not exit it even after normal interactions that
    should cause it to exit. Note: This issue only affected Firefox for Android. Other operating systems
    are unaffected. (CVE-2021-29983)

  - Instruction reordering resulted in a sequence of instructions that would cause an object to be incorrectly
    considered during garbage collection. This led to memory corruption and a potentially exploitable crash.
    (CVE-2021-29984)

  - Uninitialized memory in a canvas object could have caused an incorrect free() leading to memory corruption
    and a potentially exploitable crash. (CVE-2021-29980)

  - After requesting multiple permissions, and closing the first permission panel, subsequent permission
    panels will be displayed in a different position but still record a click in the default location, making
    it possible to trick a user into accepting a permission they did not want to.This bug only affects
    Firefox on Linux. Other operating systems are unaffected. (CVE-2021-29987)

  - A use-after-free vulnerability in media channels could have led to memory corruption and a potentially
    exploitable crash. (CVE-2021-29985)

  - Due to incorrect JIT optimization, we incorrectly interpreted data from the wrong type of object,
    resulting in the potential leak of a single bit of memory. (CVE-2021-29982)

  - Mozilla developers Christoph Kerschbaumer, Olli Pettay, Sandor Molnar, and Simon Giesecke reported memory
    safety bugs present in Firefox 90 and Firefox ESR 78.12. Some of these bugs showed evidence of memory
    corruption and we presume that with enough effort some of these could have been exploited to run arbitrary
    code. (CVE-2021-29989)

  - Mozilla developers and community members Kershaw Chang, Philipp, Chris Peterson, and Sebastian Hengst
    reported memory safety bugs present in Firefox 90. Some of these bugs showed evidence of memory corruption
    and we presume that with enough effort some of these could have been exploited to run arbitrary code.
    (CVE-2021-29990)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2021-33/");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Mozilla Firefox version 91.0 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-29990");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/08/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/08/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/08/10");

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

mozilla_check_version(installs:installs, product:'firefox', esr:FALSE, fix:'91.0', severity:SECURITY_WARNING);
