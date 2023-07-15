#
# (C) Tenable Network Security, Inc.
#


# The descriptive text and package checks in this plugin were
# extracted from Mozilla Foundation Security Advisory mfsa2020-12.
# The text itself is copyright (C) Mozilla Foundation.


include('compat.inc');

if (description)
{
  script_id(135275);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/04/09");

  script_cve_id(
    "CVE-2020-6821",
    "CVE-2020-6822",
    "CVE-2020-6823",
    "CVE-2020-6824",
    "CVE-2020-6825",
    "CVE-2020-6826"
  );
  script_xref(name:"MFSA", value:"2020-12");

  script_name(english:"Mozilla Firefox < 75.0 Multiple Vulnerabilities (mfsa2020-12)");

  script_set_attribute(attribute:"synopsis", value:
"A web browser installed on the remote macOS or Mac OS X host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Firefox installed on the remote macOS or Mac OS X host is prior to 75.0. It is, therefore, affected by
multiple vulnerabilities as referenced in the mfsa2020-12 advisory. 

  - Mozilla developers and community members Tyson Smith and Christian Holler reported 
    memory safety bugs present in Firefox 74 and Firefox ESR 68.6. Some of these bugs 
    showed evidence of memory corruption and we presume that with enough effort some of 
    these could have been exploited to run arbitrary code. (CVE-2020-6825) 

  - When reading from areas partially or fully outside the source resource with WebGL's 
    copyTexSubImage method, the specification requires the returned values be zero. 
    Previously, this memory was uninitialized, leading to potentially sensitive data 
    disclosure. (CVE-2020-6821)

  - On 32-bit builds, an out of bounds write could have occurred when processing an image
    larger than 4 GB in GMPDecodeData. It is possible that with enough effort this could 
    have been exploited to run arbitrary code. (CVE-2020-6822) 

  - A malicious extension could have called browser.identity.launchWebAuthFlow, 
    controlling the redirect_uri, and through the Promise returned, obtain the Auth 
    code and gain access to the user's account at the service provider. (CVE-2020-6823)

  - Initially, a user opens a Private Browsing Window and generates a password for a site,
    then closes the Private Browsing Window but leaves Firefox open. Subsequently, if the
    user had opened a new Private Browsing Window, revisited the same site, and generated
    a new password - the generated passwords would have been identical, rather than
    independent. (CVE-2020-6824) 

  - Mozilla developers Tyson Smith, Bob Clary, and Alexandru Michis reported memory 
    safety bugs present in Firefox 74. Some of these bugs showed evidence of memory 
    corruption and we presume that with enough effort some of these could have been 
    exploited to run arbitrary code. (CVE-2020-6826)

Note that Nessus has not tested for this issue but has
instead relied only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2020-12/");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Mozilla Firefox version 75.0 or later.");
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
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mozilla:firefox");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("macosx_firefox_installed.nasl");
  script_require_keys("MacOSX/Firefox/Installed");

  exit(0);
}

include('mozilla_version.inc');

kb_base = 'MacOSX/Firefox';
get_kb_item_or_exit(kb_base+'/Installed');

version = get_kb_item_or_exit(kb_base+'/Version', exit_code:1);
path = get_kb_item_or_exit(kb_base+'/Path', exit_code:1);

is_esr = get_kb_item(kb_base+'/is_esr');
if (is_esr) exit(0, 'The Mozilla Firefox installation is in the ESR branch.');

mozilla_check_version(version:version, path:path, product:'firefox', esr:FALSE, fix:'75.0', severity:SECURITY_HOLE);