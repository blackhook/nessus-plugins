#
# (C) Tenable Network Security, Inc.
#

# The descriptive text and package checks in this plugin were
# extracted from Mozilla Foundation Security Advisory mfsa2020-43.
# The text itself is copyright (C) Mozilla Foundation.

include('compat.inc');

if (description)
{
  script_id(140734);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/10/30");

  script_cve_id(
    "CVE-2020-15673",
    "CVE-2020-15676",
    "CVE-2020-15677",
    "CVE-2020-15678"
  );
  script_xref(name:"MFSA", value:"2020-43");
  script_xref(name:"IAVA", value:"2020-A-0435-S");

  script_name(english:"Mozilla Firefox ESR < 78.3");

  script_set_attribute(attribute:"synopsis", value:
"A web browser installed on the remote Windows host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Firefox ESR installed on the remote Windows host is prior to 78.3. It is, therefore, affected by multiple
vulnerabilities as referenced in the mfsa2020-43 advisory.

  - By exploiting an Open Redirect vulnerability on a website, an attacker could have spoofed the site
    displayed in the download file dialog to show the original site (the one suffering from the open redirect)
    rather than the site the file was actually downloaded from. (CVE-2020-15677)

  - Firefox sometimes ran the onload handler for SVG elements that the DOM sanitizer decided to remove,
    resulting in JavaScript being executed after pasting attacker-controlled data into a contenteditable
    element. (CVE-2020-15676)

  - When recursing through graphical layers while scrolling, an iterator may have become invalid, resulting in
    a potential use-after-free. This occurs because the function
    APZCTreeManager::ComputeClippedCompositionBounds did not follow iterator invalidation rules.
    (CVE-2020-15678)

  - Mozilla developer Jason Kratzer reported memory safety bugs present in Firefox 80 and Firefox ESR 78.2.
    Some of these bugs showed evidence of memory corruption and we presume that with enough effort some of
    these could have been exploited to run arbitrary code. (CVE-2020-15673)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2020-43/");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Mozilla Firefox ESR version 78.3 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-15678");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/09/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/09/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/09/22");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mozilla:firefox_esr");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("mozilla_org_installed.nasl");
  script_require_keys("Mozilla/Firefox/Version");

  exit(0);
}

include('mozilla_version.inc');

port = get_kb_item('SMB/transport');
if (!port) port = 445;

installs = get_kb_list('SMB/Mozilla/Firefox/*');
if (isnull(installs)) audit(AUDIT_NOT_INST, 'Firefox');

mozilla_check_version(installs:installs, product:'firefox', esr:TRUE, fix:'78.3', min:'78.0.0', severity:SECURITY_WARNING);
