## 
# (C) Tenable, Inc.
#                                  
# The descriptive text and package checks in this plugin were
# extracted from Mozilla Foundation Security Advisory mfsa2022-26.
# The text itself is copyright (C) Mozilla Foundation.
##

include('compat.inc');

if (description)
{
  script_id(162671);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/01/06");

  script_cve_id(
    "CVE-2022-2200",
    "CVE-2022-2226",
    "CVE-2022-31744",
    "CVE-2022-34468",
    "CVE-2022-34470",
    "CVE-2022-34472",
    "CVE-2022-34478",
    "CVE-2022-34479",
    "CVE-2022-34481",
    "CVE-2022-34484"
  );
  script_xref(name:"IAVA", value:"2022-A-0226-S");

  script_name(english:"Mozilla Thunderbird < 91.11");

  script_set_attribute(attribute:"synopsis", value:
"A mail client installed on the remote Windows host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Thunderbird installed on the remote Windows host is prior to 91.11. It is, therefore, affected by
multiple vulnerabilities as referenced in the mfsa2022-26 advisory.

  - A malicious website that could create a popup could have resized the popup to overlay the address bar with
    its own content, resulting in potential user confusion or spoofing attacks.   This bug only affects
    Thunderbird for Linux. Other operating systems are unaffected. (CVE-2022-34479)

  - Navigations between XML documents may have led to a use-after-free and potentially exploitable crash.
    (CVE-2022-34470)

  - An iframe that was not permitted to run scripts could do so if the user clicked on a
    <code>javascript:</code> link. (CVE-2022-34468)

  - An OpenPGP digital signature includes information about the date when the signature was created. When
    displaying an email that contains a digital signature, the email's date will be shown. If the dates were
    different, then Thunderbird didn't report the email as having an invalid signature. If an attacker
    performed a replay attack, in which an old email with old contents are resent at a later time, it could
    lead the victim to believe that the statements in the email are current. Fixed versions of Thunderbird
    will require that the signature's date roughly matches the displayed date of the email. (CVE-2022-2226)

  - In the <code>nsTArrayImpl::ReplaceElementsAt()</code> function, an integer overflow could have occurred
    when the number of elements to replace was too large for the container. (CVE-2022-34481)

  - An attacker could have injected CSS into stylesheets accessible via internal URIs, such as resource:, and
    in doing so bypass a page's Content Security Policy. (CVE-2022-31744)

  - If there was a PAC URL set and the server that hosts the PAC was not reachable, OCSP requests would have
    been blocked, resulting in incorrect error pages being shown. (CVE-2022-34472)

  - The <code>ms-msdt</code>, <code>search</code>, and <code>search-ms</code> protocols deliver content to
    Microsoft applications, bypassing the browser, when a user accepts a prompt. These applications have had
    known vulnerabilities, exploited in the wild (although we know of none exploited through Thunderbird), so
    in this release Thunderbird has blocked these protocols from prompting the user to open them. This bug
    only affects Thunderbird on Windows. Other operating systems are unaffected. (CVE-2022-34478)

  - If an object prototype was corrupted by an attacker, they would have been able to set undesired attributes
    on a JavaScript object, leading to privileged code execution. (CVE-2022-2200)

  - The Mozilla Fuzzing Team reported potential vulnerabilities present in Thunderbird 91.10. Some of these
    bugs showed evidence of memory corruption and we presume that with enough effort some of these could have
    been exploited to run arbitrary code. (CVE-2022-34484)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2022-26/");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Mozilla Thunderbird version 91.11 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-34484");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2022-34470");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/06/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/06/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/07/01");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mozilla:thunderbird");
  script_set_attribute(attribute:"stig_severity", value:"I");
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

mozilla_check_version(installs:installs, product:'thunderbird', esr:FALSE, fix:'91.11', min:'91.0.0', severity:SECURITY_HOLE);
