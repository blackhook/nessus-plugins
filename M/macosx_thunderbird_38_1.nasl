#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(84578);
  script_version("1.13");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/05");

  script_cve_id(
    "CVE-2015-2721",
    "CVE-2015-2724",
    "CVE-2015-2725",
    "CVE-2015-2731",
    "CVE-2015-2734",
    "CVE-2015-2735",
    "CVE-2015-2736",
    "CVE-2015-2737",
    "CVE-2015-2738",
    "CVE-2015-2739",
    "CVE-2015-2740",
    "CVE-2015-2741",
    "CVE-2015-4000"
  );
  script_bugtraq_id(74733);
  script_xref(name:"CEA-ID", value:"CEA-2021-0004");

  script_name(english:"Mozilla Thunderbird < 38.1 Multiple Vulnerabilities (Mac OS X) (Logjam)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Mac OS X host contains a mail client that is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Thunderbird installed on the remote Mac OS X host is
prior to 38.1. It is, therefore, affected by multiple
vulnerabilities :

  - A security downgrade vulnerability exists due to a flaw
    in Network Security Services (NSS). When a client allows
    for a ECDHE_ECDSA exchange, but the server does not send 
    a ServerKeyExchange message, the NSS client will take
    the EC key from the ECDSA certificate. A remote attacker
    can exploit this to silently downgrade the exchange to a
    non-forward secret mixed-ECDH exchange. (CVE-2015-2721)

  - Multiple memory corruption issues exist that allow an
    attacker to cause a denial of service condition or
    potentially execute arbitrary code. (CVE-2015-2724,
    CVE-2015-2725)

  - A use-after-free error exists in the
    CSPService::ShouldLoad() function when modifying the
    Document Object Model to remove a DOM object. An
    attacker can exploit this to dereference already freed
    memory, potentially resulting in the execution of
    arbitrary code. (CVE-2015-2731)

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

  - A security bypass vulnerability exists due to a flaw in
    certificate pinning checks. Key pinning is not enforced
    upon encountering an X.509 certificate problem that
    generates a user dialog. A man-in-the-middle attacker
    can exploit this to bypass intended access restrictions.
    (CVE-2015-2741)

  - A man-in-the-middle vulnerability, known as Logjam,
    exists due to a flaw in the SSL/TLS protocol. A remote
    attacker can exploit this flaw to downgrade connections
    using ephemeral Diffie-Hellman key exchange to 512-bit
    export-grade cryptography. (CVE-2015-4000)");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org//en-US/security/advisories/mfsa2015-59/");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org//en-US/security/advisories/mfsa2015-63/");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org//en-US/security/advisories/mfsa2015-66/");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org//en-US/security/advisories/mfsa2015-67/");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org//en-US/security/advisories/mfsa2015-70/");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org//en-US/security/advisories/mfsa2015-71/");
  script_set_attribute(attribute:"see_also", value:"https://weakdh.org/");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Thunderbird 38.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"in_the_news", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/05/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/07/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/07/07");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mozilla:thunderbird");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2015-2022 Tenable Network Security, Inc.");

  script_dependencies("macosx_thunderbird_installed.nasl");
  script_require_keys("MacOSX/Thunderbird/Installed");

  exit(0);
}

include("mozilla_version.inc");

kb_base = "MacOSX/Thunderbird";
get_kb_item_or_exit(kb_base+"/Installed");

version = get_kb_item_or_exit(kb_base+"/Version", exit_code:1);
path = get_kb_item_or_exit(kb_base+"/Path", exit_code:1);

if (get_kb_item(kb_base + '/is_esr')) exit(0, 'The Mozilla Thunderbird install is in the ESR branch.');

mozilla_check_version(product:'thunderbird', version:version, path:path, esr:FALSE, fix:'38.1', min:'38.0', severity:SECURITY_HOLE);
