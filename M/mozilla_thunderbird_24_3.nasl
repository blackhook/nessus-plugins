#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(72332);
  script_version("1.11");
  script_cvs_date("Date: 2019/11/26");

  script_cve_id(
    "CVE-2014-1477",
    "CVE-2014-1479",
    "CVE-2014-1481",
    "CVE-2014-1482",
    "CVE-2014-1486",
    "CVE-2014-1487",
    "CVE-2014-1490",
    "CVE-2014-1491"
  );
  script_bugtraq_id(
    65317,
    65320,
    65326,
    65328,
    65330,
    65332,
    65334,
    65335
  );

  script_name(english:"Mozilla Thunderbird < 24.3 Multiple Vulnerabilities");
  script_summary(english:"Checks version of Thunderbird");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains a mail client that is potentially
affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The installed version of Thunderbird is earlier than 24.3 and is,
therefore, potentially affected the following vulnerabilities:

  - Memory issues exist in the browser engine that could
    result in a denial of service or arbitrary code
    execution. (CVE-2014-1477)

  - An error exists related to System Only Wrappers (SOW)
    and the XML Binding Language (XBL) that could allow
    XUL content to be disclosed. (CVE-2014-1479)

  - An error exists related to the JavaScript engine and
    'window' object handling that has unspecified impact.
    (CVE-2014-1481)

  - An error exists related to 'RasterImage' and image
    decoding that could allow application crashes and
    possibly arbitrary code execution. (CVE-2014-1482)

  - A use-after-free error exists related to image handling
    and 'imgRequestProxy' that could allow application
    crashes and possibly arbitrary code execution.
    (CVE-2014-1486)

  - An error exists related to 'web workers' that could
    allow cross-origin information disclosure.
    (CVE-2014-1487)

  - Network Security Services (NSS) contains a race
    condition in libssl that occurs during session ticket 
    processing. A remote attacker can exploit this flaw
    to cause a denial of service. (CVE-2014-1490)

  - Network Security Services (NSS) does not properly
    restrict public values in Diffie-Hellman key exchanges,
    allowing a remote attacker to bypass cryptographic
    protection mechanisms. (CVE-2014-1491)");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-14-058/");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2014-01/");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2014-02/");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2014-04/");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2014-08/");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2014-09/");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2014-12/");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2014-13/");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Thunderbird 24.3 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2014-1486");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/02/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/02/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/02/05");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mozilla:thunderbird");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2014-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("mozilla_org_installed.nasl");
  script_require_keys("Mozilla/Thunderbird/Version");

  exit(0);
}

include("mozilla_version.inc");

port = get_kb_item("SMB/transport");
if (!port) port = 445;

installs = get_kb_list("SMB/Mozilla/Thunderbird/*");
if (isnull(installs)) audit(AUDIT_NOT_INST, "Thunderbird");

mozilla_check_version(installs:installs, product:'thunderbird', esr:FALSE, fix:'24.3', severity:SECURITY_HOLE, xss:FALSE);
