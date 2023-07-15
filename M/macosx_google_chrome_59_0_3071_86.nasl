#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(100680);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/25");

  script_cve_id(
    "CVE-2017-5070",
    "CVE-2017-5071",
    "CVE-2017-5072",
    "CVE-2017-5073",
    "CVE-2017-5074",
    "CVE-2017-5075",
    "CVE-2017-5076",
    "CVE-2017-5077",
    "CVE-2017-5078",
    "CVE-2017-5079",
    "CVE-2017-5080",
    "CVE-2017-5081",
    "CVE-2017-5082",
    "CVE-2017-5083",
    "CVE-2017-5085",
    "CVE-2017-5086"
  );
  script_bugtraq_id(98861);
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/06/22");

  script_name(english:"Google Chrome < 59.0.3071.86 Multiple Vulnerabilities (macOS)");

  script_set_attribute(attribute:"synopsis", value:
"A web browser installed on the remote macOS or Mac OS X host is
affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Google Chrome installed on the remote macOS or Mac OS X
host is prior to 59.0.3071.86. It is, therefore, affected by the
following vulnerabilities :

  - A type confusion error exists in the Google V8 component
    that allows an unauthenticated, remote attacker to
    execute arbitrary code. (CVE-2017-5070)

  - An out-of-bounds read error exists in the Google V8
    component that allows an unauthenticated, remote
    attacker to cause a denial of service condition or the
    disclosure of sensitive information. (CVE-2017-5071)

  - Multiple unspecified flaws exist in the Omnibox
    component that allows an attacker to spoof the address
    in the address bar. (CVE-2017-5072, CVE-2017-5076,
    CVE-2017-5083, CVE-2017-5086)

  - A use-after-free error exists in the print preview
    functionality that allows an unauthenticated, remote
    attacker to execute arbitrary code. (CVE-2017-5073)

  - A use-after-free error exists in the Apps Bluetooth
    component that allows an unauthenticated, remote
    attacker to execute arbitrary code. (CVE-2017-5074)

  - An unspecified flaw exists in the CSP reporting
    component that allows an unauthenticated, remote
    attacker to disclose sensitive information.
    (CVE-2017-5075)

  - An overflow condition exists in the Google Skia
    component due to improper validation of user-supplied
    input. An unauthenticated, remote attacker can exploit
    this, by convincing a user to visit a specially crafted
    website, to cause a denial of service condition or the
    execution of arbitrary code. (CVE-2017-5077)

  - An unspecified flaw exists in the mailto handling
    functionality that allows an unauthenticated, remote
    attacker to inject arbitrary commands. (CVE-2017-5078)

  - An unspecified flaw exists in Blink that allows an
    attacker to spoof components in the user interface.
    (CVE-2017-5079)

  - A use-after-free free error exists in the credit card
    autofill functionality that allows an attacker to have
    an unspecified impact. (CVE-2017-5080)

  - An unspecified flaw exists that allows an
    unauthenticated, remote attacker to bypass extension
    verification mechanisms. (CVE-2017-5081)

  - An unspecified flaw exists in the credit card editor
    view functionality that allows an unauthenticated,
    remote attacker to disclose credit card information.
    (CVE-2017-5082)

  - An unspecified flaw exists in the WebUI pages component
    that allows an unauthenticated, remote attacker to
    execute arbitrary JavaScript code. (CVE-2017-5085)

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  # https://chromereleases.googleblog.com/2017/06/stable-channel-update-for-desktop.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?6dde93a4");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Google Chrome version 59.0.3071.86 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-5080");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/06/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/06/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/06/08");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:google:chrome");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2017-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("macosx_google_chrome_installed.nbin");
  script_require_keys("MacOSX/Google Chrome/Installed");

  exit(0);
}

include("google_chrome_version.inc");

get_kb_item_or_exit("MacOSX/Google Chrome/Installed");

google_chrome_check_version(fix:'59.0.3071.86', severity:SECURITY_WARNING);

