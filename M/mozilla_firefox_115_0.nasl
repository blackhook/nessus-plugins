#%NASL_MIN_LEVEL 80900
## 
# (C) Tenable, Inc.
#                                  
# The descriptive text and package checks in this plugin were
# extracted from Mozilla Foundation Security Advisory mfsa2023-22.
# The text itself is copyright (C) Mozilla Foundation.
##

include('compat.inc');

if (description)
{
  script_id(177932);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/07/06");

  script_cve_id(
    "CVE-2023-3482",
    "CVE-2023-37201",
    "CVE-2023-37202",
    "CVE-2023-37203",
    "CVE-2023-37204",
    "CVE-2023-37205",
    "CVE-2023-37206",
    "CVE-2023-37207",
    "CVE-2023-37208",
    "CVE-2023-37209",
    "CVE-2023-37210",
    "CVE-2023-37211",
    "CVE-2023-37212"
  );
  script_xref(name:"IAVA", value:"2023-A-0328");

  script_name(english:"Mozilla Firefox < 115.0");

  script_set_attribute(attribute:"synopsis", value:
"A web browser installed on the remote Windows host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Firefox installed on the remote Windows host is prior to 115.0. It is, therefore, affected by multiple
vulnerabilities as referenced in the mfsa2023-22 advisory.

  - When Firefox is configured to block storage of all cookies, it was still possible to store data in
    localstorage by using an iframe with a source of 'about:blank'. This could have led to malicious websites
    storing tracking data without permission. (CVE-2023-3482)

  - An attacker could have triggered a use-after-free condition when creating a WebRTC connection over HTTPS.
    (CVE-2023-37201)

  - Cross-compartment wrappers wrapping a scripted proxy could have caused objects from other compartments to
    be stored in the main compartment resulting in a use-after-free. (CVE-2023-37202)

  - Insufficient validation in the Drag and Drop API in conjunction with social engineering, may have allowed
    an attacker to trick end-users into creating a shortcut to local system files.  This could have been
    leveraged to execute arbitrary code. (CVE-2023-37203)

  - A website could have obscured the fullscreen notification by using an option element by introducing lag
    via an expensive computational function. This could have led to user confusion and possible spoofing
    attacks. (CVE-2023-37204)

  - The use of RTL Arabic characters in the address bar may have allowed for URL spoofing. (CVE-2023-37205)

  - Uploading files which contain symlinks may have allowed an attacker to trick a user into submitting
    sensitive data to a malicious website. (CVE-2023-37206)

  - A website could have obscured the fullscreen notification by using a URL with a scheme handled by an
    external program, such as a mailto URL. This could have led to user confusion and possible spoofing
    attacks. (CVE-2023-37207)

  - When opening Diagcab files, Firefox did not warn the user that these files may contain malicious code.
    (CVE-2023-37208)

  - A use-after-free condition existed in `NotifyOnHistoryReload` where a `LoadingSessionHistoryEntry` object
    was freed and a reference to that object remained.  This resulted in a potentially exploitable condition
    when the reference to that object was later reused. (CVE-2023-37209)

  - A website could prevent a user from exiting full-screen mode via alert and prompt calls.  This could lead
    to user confusion and possible spoofing attacks. (CVE-2023-37210)

  - Memory safety bugs present in Firefox 114, Firefox ESR 102.12, and Thunderbird 102.12. Some of these bugs
    showed evidence of memory corruption and we presume that with enough effort some of these could have been
    exploited to run arbitrary code. (CVE-2023-37211)

  - Memory safety bugs present in Firefox 114. Some of these bugs showed evidence of memory corruption and we
    presume that with enough effort some of these could have been exploited to run arbitrary code.
    (CVE-2023-37212)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2023-22/");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Mozilla Firefox version 115.0 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-37211");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/07/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/07/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/07/04");

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

mozilla_check_version(installs:installs, product:'firefox', esr:FALSE, fix:'115.0', severity:SECURITY_HOLE);
