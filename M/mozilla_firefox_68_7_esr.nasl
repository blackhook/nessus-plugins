#
# (C) Tenable Network Security, Inc.
#


# The descriptive text and package checks in this plugin were
# extracted from Mozilla Foundation Security Advisory mfsa2020-13.
# The text itself is copyright (C) Mozilla Foundation.


include('compat.inc');

if (description)
{
  script_id(135274);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/04/09");

  script_cve_id(
    "CVE-2020-6821",
    "CVE-2020-6822",
    "CVE-2020-6825",
    "CVE-2020-6827",
    "CVE-2020-6828"
  );
  script_xref(name:"MFSA", value:"2020-13");

  script_name(english:"Mozilla Firefox ESR < 68.7 Multiple Vulnerabilities (mfsa2020-13)");

  script_set_attribute(attribute:"synopsis", value:
"A web browser installed on the remote Windows host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Firefox ESR installed on the remote Windows host is prior to 68.7. It is, therefore, affected by multiple
vulnerabilities as referenced in the mfsa2020-13 advisory.

  - A malicious Android application could craft an Intent
    that would have been processed by Firefox for Android
    and potentially result in a file overwrite in the user's
    profile directory. One exploitation vector for this
    would be to supply a user.js file providing arbitrary
    malicious preference values. Control of arbitrary
    preferences can lead to sufficient compromise such that
    it is generally equivalent to arbitrary code
    execution. Note: This issue only affects Firefox for
    Android. Other operating systems are unaffected.
    (CVE-2020-6828)

  - When following a link that opened an intent://-schemed
    URL, causing a custom tab to be opened, Firefox for
    Android could be tricked into displaying the incorrect
    URI.  Note: This issue only affects Firefox for
    Android. Other operating systems are unaffected.
    (CVE-2020-6827)

  - When reading from areas partially or fully outside the
    source resource with WebGL's
    copyTexSubImage method, the specification
    requires the returned values be zero. Previously, this
    memory was uninitialized, leading to potentially
    sensitive data disclosure. (CVE-2020-6821)

  - On 32-bit builds, an out of bounds write could have
    occurred when processing an image larger than 4 GB in
    GMPDecodeData. It is possible that with
    enough effort this could have been exploited to run
    arbitrary code. (CVE-2020-6822)

  - Mozilla developers Tyson Smith and Christian Holler
    reported memory safety bugs present in Firefox 74 and
    Firefox ESR 68.6. Some of these bugs showed evidence of
    memory corruption and we presume that with enough effort
    some of these could have been exploited to run arbitrary
    code. (CVE-2020-6825)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2020-13/");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Mozilla Firefox ESR version 68.7 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-6825");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/04/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/04/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/04/07");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mozilla:firefox_esr");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("mozilla_org_installed.nasl");
  script_require_keys("Mozilla/Firefox/Version");

  exit(0);
}

include('mozilla_version.inc');

port = get_kb_item("SMB/transport");
if (!port) port = 445;

installs = get_kb_list("SMB/Mozilla/Firefox/*");
if (isnull(installs)) audit(AUDIT_NOT_INST, "Firefox");

mozilla_check_version(installs:installs, product:'firefox', esr:TRUE, fix:'68.7', min:'68.0.0', severity:SECURITY_HOLE);