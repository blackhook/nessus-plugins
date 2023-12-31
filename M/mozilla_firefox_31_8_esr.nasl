#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(84579);
  script_version("1.14");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/05");

  script_cve_id(
    "CVE-2015-2721",
    "CVE-2015-2722",
    "CVE-2015-2724",
    "CVE-2015-2728",
    "CVE-2015-2730",
    "CVE-2015-2733",
    "CVE-2015-2734",
    "CVE-2015-2735",
    "CVE-2015-2736",
    "CVE-2015-2737",
    "CVE-2015-2738",
    "CVE-2015-2739",
    "CVE-2015-2740",
    "CVE-2015-2743",
    "CVE-2015-4000"
  );
  script_bugtraq_id(74733);
  script_xref(name:"CEA-ID", value:"CEA-2021-0004");

  script_name(english:"Firefox ESR < 31.8 Multiple Vulnerabilities (Logjam)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains a web browser that is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Firefox ESR installed on the remote Windows host is
prior to 31.8. It is, therefore, affected by multiple
vulnerabilities :

  - A security downgrade vulnerability exists due to a flaw
    in Network Security Services (NSS). When a client allows
    for a ECDHE_ECDSA exchange, but the server does not send 
    a ServerKeyExchange message, the NSS client will take
    the EC key from the ECDSA certificate. A remote attacker
    can exploit this to silently downgrade the exchange to a
    non-forward secret mixed-ECDH exchange. (CVE-2015-2721)

  - Multiple user-after-free errors exist when using an
    XMLHttpRequest object in concert with either shared or
    dedicated workers. A remote attacker can exploit this
    to cause a denial of service condition. (CVE-2015-2722,
    CVE-2015-2733)

  - Multiple memory corruption issues exist that allow an
    attacker to cause a denial of service condition or
    potentially execute arbitrary code. (CVE-2015-2724)

  - A type confusion flaw exists in the Indexed Database
    Manager's handling of IDBDatabase. A remote attacker can
    exploit this to cause a denial of service condition or
    to execute arbitrary code. (CVE-2015-2728)

  - A signature spoofing vulnerability exists due to a flaw
    in Network Security Services (NSS) in its Elliptic Curve
    Digital Signature Algorithm (ECDSA) signature
    validation. A remote attacker can exploit this to forge
    signatures. (CVE-2015-2730)

  - An uninitialized memory use issue exists in the
    CairoTextureClientD3D9::BorrowDrawTarget() function, the
    ::d3d11::SetBufferData() function, and the
    YCbCrImageDataDeserializer::ToDataSourceSurface()
    function. The impact is unspecified. (CVE-2015-2734,
    CVE-2015-2737, CVE-2015-2738)

  - A memory corruption issue exists in the
    nsZipArchive::GetDataOffset() function due to improper
    string length checks. An attacker can exploit this, via
    a crafted ZIP archive, to potentially execute arbitrary
    code. (CVE-2015-2735)

  - A memory corruption issue exists in the
    nsZipArchive::BuildFileList() function due to improper
    validation of user-supplied input. An attacker can
    exploit this, via a crafted ZIP archive, to potentially
    execute arbitrary code. (CVE-2015-2736)

  - An unspecified memory corruption issue exists in the
    ArrayBufferBuilder::append() function due to improper
    validation of user-supplied input. An attacker can
    exploit this to potentially execute arbitrary code.
    (CVE-2015-2739)

  - A buffer overflow condition exists in the
    nsXMLHttpRequest::AppendToResponseText() function due to
    improper validation of user-supplied input. An attacker
    can exploit this to potentially execute arbitrary code.
    (CVE-2015-2740)

  - A privilege escalation vulnerability exists in the PDF
    viewer (PDF.js) due to internal workers being executed
    insecurely. An attacker can exploit this, by leveraging
    a Same Origin Policy bypass, to execute arbitrary code.
    (CVE-2015-2743)

  - A man-in-the-middle vulnerability, known as Logjam,
    exists due to a flaw in the SSL/TLS protocol. A remote
    attacker can exploit this flaw to downgrade connections
    using ephemeral Diffie-Hellman key exchange to 512-bit
    export-grade cryptography. (CVE-2015-4000)");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org//en-US/security/advisories/mfsa2015-59/");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org//en-US/security/advisories/mfsa2015-61/");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org//en-US/security/advisories/mfsa2015-64/");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org//en-US/security/advisories/mfsa2015-65/");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org//en-US/security/advisories/mfsa2015-66/");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org//en-US/security/advisories/mfsa2015-69/");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org//en-US/security/advisories/mfsa2015-70/");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org//en-US/security/advisories/mfsa2015-71/");
  script_set_attribute(attribute:"see_also", value:"https://weakdh.org/");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Firefox ESR 31.8 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2015-2740");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"in_the_news", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/05/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/07/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/07/07");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mozilla:firefox_esr");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2015-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("mozilla_org_installed.nasl");
  script_require_keys("Mozilla/Firefox/Version");

  exit(0);
}

include("mozilla_version.inc");

port = get_kb_item("SMB/transport");
if (!port) port = 445;

installs = get_kb_list("SMB/Mozilla/Firefox/*");
if (isnull(installs)) audit(AUDIT_NOT_INST, "Firefox");

mozilla_check_version(installs:installs, product:'firefox', esr:TRUE, fix:'31.8', min:'31.0', severity:SECURITY_HOLE);
