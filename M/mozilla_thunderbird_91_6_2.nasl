#%NASL_MIN_LEVEL 70300
## 
# (C) Tenable Network Security, Inc.
#                                  
# The descriptive text and package checks in this plugin were
# extracted from Mozilla Foundation Security Advisory mfsa2022-09.
# The text itself is copyright (C) Mozilla Foundation.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(158653);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/25");

  script_cve_id("CVE-2022-26485", "CVE-2022-26486");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/03/21");

  script_name(english:"Mozilla Thunderbird < 91.6.2");

  script_set_attribute(attribute:"synopsis", value:
"A mail client installed on the remote Windows host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Thunderbird installed on the remote Windows host is prior to 91.6.2. It is, therefore, affected by
multiple vulnerabilities as referenced in the mfsa2022-09 advisory.

  - Removing an XSLT parameter during processing could have lead to an exploitable use-after-free. We have had
    reports of attacks in the wild abusing this flaw. (CVE-2022-26485)

  - An unexpected message in the WebGPU IPC framework could lead to a use-after-free and exploitable sandbox
    escape.  We have had reports of attacks in the wild abusing this flaw. (CVE-2022-26486)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2022-09/");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Mozilla Thunderbird version 91.6.2 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-26486");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/03/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/03/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/03/07");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mozilla:thunderbird");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("mozilla_org_installed.nasl");
  script_require_keys("Mozilla/Thunderbird/Version");

  exit(0);
}

include('mozilla_version.inc');

var port = get_kb_item('SMB/transport');
if (!port) port = 445;

var installs = get_kb_list('SMB/Mozilla/Thunderbird/*');
if (isnull(installs)) audit(AUDIT_NOT_INST, 'Thunderbird');

mozilla_check_version(installs:installs, product:'thunderbird', esr:FALSE, fix:'91.6.2', severity:SECURITY_HOLE);
