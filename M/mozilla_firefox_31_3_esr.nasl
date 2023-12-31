#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(79664);
  script_version("1.10");
  script_cvs_date("Date: 2019/11/25");

  script_cve_id(
    "CVE-2014-1569",
    "CVE-2014-1587",
    "CVE-2014-1588",
    "CVE-2014-1590",
    "CVE-2014-1592",
    "CVE-2014-1593",
    "CVE-2014-1594"
  );
  script_bugtraq_id(
    71391,
    71392,
    71395,
    71396,
    71397,
    71398,
    71675
  );

  script_name(english:"Firefox ESR 31.x < 31.3 Multiple Vulnerabilities");
  script_summary(english:"Checks the version of Firefox.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains a web browser that is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Firefox ESR 31.x installed on the remote Windows host
is prior to 31.3. It is, therefore, affected by the following
vulnerabilities :

  - A remote code execution vulnerability exists in Mozilla
    Network Security Services (NSS) due to a flaw in
    'quickder.c' that is triggered when handling PKCS#1
    signatures during the decoding of ASN.1 DER.
    (CVE-2014-1569)

  - Multiple memory safety flaws exist within the browser
    engine. Exploiting these, an attacker can cause a denial
    of service or execute arbitrary code. (CVE-2014-1587,
    CVE-2014-1588)

  - A denial of service vulnerability exists due to
    improper parsing of a JavaScript object to the
    XMLHttpRequest API which can result in a crash.
    (CVE-2014-1590)

  - A use-after-free error exists due the creation of a
    second XML root element when parsing HTML written to a
    document created with 'document.open()' function which
    can result in arbitrary code execution. (CVE-2014-1592)

  - A buffer overflow vulnerability exists in the
    'mozilla::FileBlockCache::Read' function when parsing
    media which can result in arbitrary code execution.
    (CVE-2014-1593)

  - A casting error exists when casting from the
    'BasicThebesLayer' layer to the 'BasicContainerLayer'
    layer which can result in arbitrary code execution.
    (CVE-2014-1594)");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/security/announce/2014/mfsa2014-83.html");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/security/announce/2014/mfsa2014-85.html");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/security/announce/2014/mfsa2014-87.html");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/security/announce/2014/mfsa2014-88.html");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/security/announce/2014/mfsa2014-89.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Firefox ESR 31.3 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2014-1569");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/12/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/12/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/12/02");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mozilla:firefox_esr");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2014-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("mozilla_org_installed.nasl");
  script_require_keys("Mozilla/Firefox/Version");

  exit(0);
}

include("mozilla_version.inc");

port = get_kb_item("SMB/transport");
if (!port) port = 445;

installs = get_kb_list("SMB/Mozilla/Firefox/*");
if (isnull(installs)) audit(AUDIT_NOT_INST, "Firefox");

mozilla_check_version(installs:installs, product:'firefox', esr:TRUE, fix:'31.3', min:'31.0', severity:SECURITY_HOLE, xss:FALSE);
