#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(81521);
  script_version("1.9");
  script_cvs_date("Date: 2019/11/25");

  script_cve_id(
    "CVE-2015-0819",
    "CVE-2015-0820",
    "CVE-2015-0821",
    "CVE-2015-0822",
    "CVE-2015-0823",
    "CVE-2015-0824",
    "CVE-2015-0825",
    "CVE-2015-0826",
    "CVE-2015-0827",
    "CVE-2015-0828",
    "CVE-2015-0829",
    "CVE-2015-0830",
    "CVE-2015-0831",
    "CVE-2015-0832",
    "CVE-2015-0833",
    "CVE-2015-0834",
    "CVE-2015-0835",
    "CVE-2015-0836"
  );
  script_bugtraq_id(
    72741,
    72742,
    72743,
    72744,
    72745,
    72746,
    72747,
    72748,
    72750,
    72751,
    72752,
    72753,
    72754,
    72755,
    72756,
    72757,
    72758,
    72759
  );

  script_name(english:"Firefox < 36 Multiple Vulnerabilities");
  script_summary(english:"Checks the version of Firefox.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains a web browser that is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Firefox installed on the remote Windows host is prior
to 36.0. It is, therefore, affected by the following vulnerabilities :

  - An issue exists that allows whitelisted Mozilla domains
    to make 'UITour' API calls while UI Tour pages are
    present in background tabs. This allows an attacker, via
    a compromised Mozilla domain, to engage in spoofing and
    clickjacking in any foreground tab. (CVE-2015-0819)

  - An issue exists related to sandbox libraries, including
    the Caja Compiler, which allows JavaScript objects to be
    marked as extensible even though the objects were
    initially marked as non-extensible. (CVE-2015-0820)

  - An issue exists when opening hyperlinks on a page with
    the mouse and specific keyboard key combinations that
    allows a Chrome privileged URL to be opened without
    context restrictions being preserved. Additionally, the
    issue allows the opening of local files and resources
    from a known location to be opened with local
    privileges, bypassing security protections.
    (CVE-2015-0821)

  - An information disclosure vulnerability exists related
    to the autocomplete feature that allows an attacker to
    read arbitrary files. (CVE-2015-0822)

  - A use-after-free error exists with the OpenType
    Sanitiser (OTS) when expanding macros. (CVE-2015-0823)

  - An issue exists in the DrawTarget() function of the
    Cairo graphics library that allows an attacker cause a
    segmentation fault, resulting in a denial of service.
    (CVE-2015-0824)

  - A buffer underflow issue exists during audio playback of
    invalid MP3 audio files. (CVE-2015-0825)

  - An out-of-bounds read issue exists while restyling and
    reflowing changes of web content with CSS, resulting in
    a denial of service condition or arbitrary code
    execution. (CVE-2015-0826)

  - An out-of-bounds read and write issue exists when
    processing invalid SVG graphic files. This allows an
    attacker to disclose sensitive information.
    (CVE-2015-0827)

  - A double-free issue exists when sending a zero-length
    XmlHttpRequest (XHR) object due to errors in memory
    allocation when using different memory allocator
    libraries than 'jemalloc'. This allows an attacker to
    crash the application. (CVE-2015-0828)

  - A buffer overflow issue exists in the 'libstagefright'
    library when processing invalid MP4 video files,
    resulting in a denial of service condition or arbitrary
    code execution. (CVE-2015-0829)

  - An unspecified issue exists that allows an attacker, via
    specially crafted WebGL content, to cause a denial of
    service condition. (CVE-2015-0830)

  - A use-after-free issue exists when running specific web
    content with 'IndexedDB' to create an index, resulting
    in a denial of service condition or arbitrary code
    execution. (CVE-2015-0831)

  - An issue exists when a period is appended to a hostname
    that results in a bypass of the Public Key Pinning
    Extension for HTTP (HPKP) and HTTP Strict Transport
    Security (HSTS) when certificate pinning is set to
    strict mode. An attacker can exploit this issue to
    perform man-in-the-middle attacks if the attacker has a
    security certificate for a domain with the added period.
    (CVE-2015-0832)

  - An issue exists in the Mozilla updater in which DLL
    files in the current working directory or Windows
    temporary directories will be loaded, allowing the
    execution of arbitrary code. Note that hosts are only
    affected if the updater is not run by the Mozilla
    Maintenance Service. (CVE-2015-0833)

  - An information disclosure vulnerability exists due to
    the lack of TLS support for connections to TURN and STUN
    servers, resulting in cleartext connections.
    (CVE-2015-0834)

  - Multiple unspecified memory safety issues exist within
    the browser engine. (CVE-2015-0835, CVE-2015-0836)");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2015-11/");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2015-12/");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2015-13/");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2015-14/");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2015-15/");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2015-16/");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2015-17/");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2015-18/");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2015-19/");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2015-20/");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2015-21/");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2015-22/");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2015-23/");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2015-24/");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2015-25/");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2015-26/");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2015-27/");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Firefox 36.0 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2015-0836");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/02/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/02/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/02/25");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mozilla:firefox");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2015-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("mozilla_org_installed.nasl");
  script_require_keys("Mozilla/Firefox/Version");

  exit(0);
}

include("mozilla_version.inc");

port = get_kb_item("SMB/transport");
if (!port) port = 445;

installs = get_kb_list("SMB/Mozilla/Firefox/*");
if (isnull(installs)) audit(AUDIT_NOT_INST, "Firefox");

mozilla_check_version(installs:installs, product:'firefox', esr:FALSE, fix:'36', severity:SECURITY_HOLE, xss:FALSE, xsrf:FALSE);
