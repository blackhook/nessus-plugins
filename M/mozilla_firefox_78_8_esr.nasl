## 
# (C) Tenable Network Security, Inc.
#                                  
# The descriptive text and package checks in this plugin were
# extracted from Mozilla Foundation Security Advisory mfsa2021-08.
# The text itself is copyright (C) Mozilla Foundation.
##

include('compat.inc');

if (description)
{
  script_id(146781);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/06/03");

  script_cve_id(
    "CVE-2021-23968",
    "CVE-2021-23969",
    "CVE-2021-23973",
    "CVE-2021-23978"
  );
  script_xref(name:"IAVA", value:"2021-A-0107-S");

  script_name(english:"Mozilla Firefox ESR < 78.8");

  script_set_attribute(attribute:"synopsis", value:
"A web browser installed on the remote Windows host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Firefox ESR installed on the remote Windows host is prior to 78.8. It is, therefore, affected by multiple
vulnerabilities as referenced in the mfsa2021-08 advisory.

  - As specified in the W3C Content Security Policy draft, when creating a violation report, User agents need
    to ensure that the source file is the URL requested by the page, pre-redirects. If thats not possible,
    user agents need to strip the URL down to an origin to avoid unintentional leakage. Under certain types
    of redirects, Firefox incorrectly set the source file to be the destination of the redirects. This was
    fixed to be the redirect destination's origin. (CVE-2021-23969)

  - If Content Security Policy blocked frame navigation, the full destination of a redirect served in the
    frame was reported in the violation report; as opposed to the original frame URI. This could be used to
    leak sensitive information contained in such URIs. (CVE-2021-23968)

  - When trying to load a cross-origin resource in an audio/video context a decoding error may have resulted,
    and the content of that error may have revealed information about the resource. (CVE-2021-23973)

  - Mozilla developers Alexis Beingessner, Tyson Smith, Nika Layzell, and Mats Palmgren reported memory safety
    bugs present in Firefox 85 and Firefox ESR 78.7. Some of these bugs showed evidence of memory corruption
    and we presume that with enough effort some of these could have been exploited to run arbitrary code.
    (CVE-2021-23978)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2021-08/");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Mozilla Firefox ESR version 78.8 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-23978");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/02/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/02/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/02/23");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mozilla:firefox_esr");
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

mozilla_check_version(installs:installs, product:'firefox', esr:TRUE, fix:'78.8', min:'78.0.0', severity:SECURITY_WARNING);
