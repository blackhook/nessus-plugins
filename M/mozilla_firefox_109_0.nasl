#%NASL_MIN_LEVEL 80900
## 
# (C) Tenable, Inc.
#                                  
# The descriptive text and package checks in this plugin were
# extracted from Mozilla Foundation Security Advisory mfsa2023-01.
# The text itself is copyright (C) Mozilla Foundation.
##

include('compat.inc');

if (description)
{
  script_id(170099);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/02/16");

  script_cve_id(
    "CVE-2023-23597",
    "CVE-2023-23598",
    "CVE-2023-23599",
    "CVE-2023-23600",
    "CVE-2023-23601",
    "CVE-2023-23602",
    "CVE-2023-23603",
    "CVE-2023-23604",
    "CVE-2023-23605",
    "CVE-2023-23606"
  );
  script_xref(name:"IAVA", value:"2023-A-0048-S");

  script_name(english:"Mozilla Firefox < 109.0");

  script_set_attribute(attribute:"synopsis", value:
"A web browser installed on the remote Windows host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Firefox installed on the remote Windows host is prior to 109.0. It is, therefore, affected by multiple
vulnerabilities as referenced in the mfsa2023-01 advisory.

  - A compromised web child process could disable web security opening restrictions, leading to a new child
    process being spawned within the <code>file://</code> context. Given a reliable exploit primitive, this
    new process could be exploited again leading to arbitrary file read. (CVE-2023-23597)

  - Due to the Firefox GTK wrapper code's use of text/plain for drag data and GTK treating all text/plain
    MIMEs containing file URLs as being dragged a website could arbitrarily read a file via a call to
    <code>DataTransfer.setData</code>. (CVE-2023-23598)

  - When copying a network request from the developer tools panel as a curl command the output was not being
    properly sanitized and could allow arbitrary commands to be hidden within. (CVE-2023-23599)

  - Per origin notification permissions were being stored in a way that didn't take into account what browsing
    context the permission was granted in. This lead to the possibility of notifications to be displayed
    during different browsing sessions. This bug only affects Firefox for Android. Other operating systems are
    unaffected. (CVE-2023-23600)

  - Navigations were being allowed when dragging a URL from a cross-origin iframe into the same tab which
    could lead to website spoofing attacks (CVE-2023-23601)

  - A mishandled security check when creating a WebSocket in a WebWorker caused the Content Security Policy
    connect-src header to be ignored. This could lead to connections to restricted origins from inside
    WebWorkers. (CVE-2023-23602)

  - Regular expressions used to filter out forbidden properties and values from style directives in calls to
    <code>console.log</code> weren't accounting for external URLs. Data could then be potentially exfiltrated
    from the browser. (CVE-2023-23603)

  - A duplicate <code>SystemPrincipal</code> object could be created when parsing a non-system html document
    via <code>DOMParser::ParseFromSafeString</code>. This could have lead to bypassing web security checks.
    (CVE-2023-23604)

  - Mozilla developers and the Mozilla Fuzzing Team reported memory safety bugs present in Firefox 108 and
    Firefox ESR 102.6. Some of these bugs showed evidence of memory corruption and we presume that with enough
    effort some of these could have been exploited to run arbitrary code. (CVE-2023-23605)

  - Mozilla developers and the Mozilla Fuzzing Team reported memory safety bugs present in Firefox 108. Some
    of these bugs showed evidence of memory corruption and we presume that with enough effort some of these
    could have been exploited to run arbitrary code. (CVE-2023-23606)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2023-01/");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Mozilla Firefox version 109.0 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-23606");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/01/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/01/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/01/17");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mozilla:firefox");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("mozilla_org_installed.nasl");
  script_require_keys("Mozilla/Firefox/Version");

  exit(0);
}

include('mozilla_version.inc');

var port = get_kb_item('SMB/transport');
if (!port) port = 445;

var installs = get_kb_list('SMB/Mozilla/Firefox/*');
if (isnull(installs)) audit(AUDIT_NOT_INST, 'Firefox');

mozilla_check_version(installs:installs, product:'firefox', esr:FALSE, fix:'109.0', severity:SECURITY_HOLE);
