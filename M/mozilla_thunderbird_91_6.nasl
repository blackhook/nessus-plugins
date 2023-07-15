#%NASL_MIN_LEVEL 70300
## 
# (C) Tenable Network Security, Inc.
#                                  
# The descriptive text and package checks in this plugin were
# extracted from Mozilla Foundation Security Advisory mfsa2022-06.
# The text itself is copyright (C) Mozilla Foundation.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(157907);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/30");

  script_cve_id(
    "CVE-2022-22753",
    "CVE-2022-22754",
    "CVE-2022-22756",
    "CVE-2022-22759",
    "CVE-2022-22760",
    "CVE-2022-22761",
    "CVE-2022-22763",
    "CVE-2022-22764"
  );
  script_xref(name:"IAVA", value:"2022-A-0079-S");

  script_name(english:"Mozilla Thunderbird < 91.6");

  script_set_attribute(attribute:"synopsis", value:
"A mail client installed on the remote Windows host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Thunderbird installed on the remote Windows host is prior to 91.6. It is, therefore, affected by multiple
vulnerabilities as referenced in the mfsa2022-06 advisory.

  - A Time-of-Check Time-of-Use bug existed in the Maintenance (Updater) Service that could be abused to grant
    Users write access to an arbitrary directory. This could have been used to escalate to SYSTEM access. This
    bug only affects Thunderbird on Windows. Other operating systems are unaffected. (CVE-2022-22753)

  - If a user installed an extension of a particular type, the extension could have auto-updated itself and
    while doing so, bypass the prompt which grants the new version the new requested permissions.
    (CVE-2022-22754)

  - If a user was convinced to drag and drop an image to their desktop or other folder, the resulting object
    could have been changed into an executable script which would have run arbitrary code after the user
    clicked on it. (CVE-2022-22756)

  - If a document created a sandboxed iframe without <code>allow-scripts</code>, and subsequently appended an
    element to the iframe's document that e.g. had a JavaScript event handler - the event handler would have
    run despite the iframe's sandbox. (CVE-2022-22759)

  - When importing resources using Web Workers, error messages would distinguish the difference between
    <code>application/javascript</code> responses and non-script responses.  This could have been abused to
    learn information cross-origin. (CVE-2022-22760)

  - Web-accessible extension pages (pages with a moz-extension:// scheme) were not correctly enforcing the
    frame-ancestors directive when it was used in the Web Extension's Content Security Policy.
    (CVE-2022-22761)

  - When a worker is shutdown, it was possible to cause script to run late in the lifecycle, at a point after
    where it should not be possible. (CVE-2022-22763)

  - Mozilla developers and community members Paul Adenot and the Mozilla Fuzzing Team reported memory safety
    bugs present in Thunderbird 91.5. Some of these bugs showed evidence of memory corruption and we presume
    that with enough effort some of these could have been exploited to run arbitrary code. (CVE-2022-22764)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2022-06/");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Mozilla Thunderbird version 91.6 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-22759");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/02/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/02/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/02/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mozilla:thunderbird");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("mozilla_org_installed.nasl");
  script_require_keys("Mozilla/Thunderbird/Version");

  exit(0);
}

include('mozilla_version.inc');

var port = get_kb_item('SMB/transport');
if (!port) port = 445;

var installs = get_kb_list('SMB/Mozilla/Thunderbird/*');
if (isnull(installs)) audit(AUDIT_NOT_INST, 'Thunderbird');

mozilla_check_version(installs:installs, product:'thunderbird', esr:FALSE, fix:'91.6', severity:SECURITY_HOLE);
