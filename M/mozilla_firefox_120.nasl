#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(58898);
  script_version("1.15");
  script_cvs_date("Date: 2018/07/17 12:00:07");

  script_cve_id(
    "CVE-2011-1187",
    "CVE-2011-3062",
    "CVE-2012-0467",
    "CVE-2012-0468",
    "CVE-2012-0469",
    "CVE-2012-0470",
    "CVE-2012-0471",
    "CVE-2012-0472",
    "CVE-2012-0473",
    "CVE-2012-0474",
    "CVE-2012-0475",
    "CVE-2012-0477",
    "CVE-2012-0478",
    "CVE-2012-0479"
  );
  script_bugtraq_id(
    53218,
    53219,
    53220,
    53221,
    53222,
    53223,
    53224,
    53225,
    53227,
    53228,
    53229,
    53230,
    53231
  );

  script_name(english:"Firefox < 12.0 Multiple Vulnerabilities");
  script_summary(english:"Checks version of Firefox");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote Windows host contains a web browser that is affected by
multiple vulnerabilities."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The installed version of Firefox is earlier than 12.0 and thus, is
potentially affected by the following security issues :

  - An error exists with handling JavaScript errors that
    could lead to information disclosure. (CVE-2011-1187)

  - An off-by-one error exists in the 'OpenType Sanitizer'
    that could lead to out-bounds-reads and possible code
    execution. (CVE-2011-3062)

  - Memory safety issues exist that could lead
    to arbitrary code execution. (CVE-2012-0467,
    CVE-2012-0468)

  - A use-after-free error exists related to 'IDBKeyRange'
    of 'indexedDB'. (CVE-2012-0469)

  - Heap-corruption errors exist related to
    'gfxImageSurface' that could lead to possible code
    execution. (CVE-2012-0470)

  - A multi-octet encoding issue exists that could allow
    cross-site scripting attacks as certain octets in
    multibyte character sets can destroy following octets.
    (CVE-2012-0471)

  - An error exists related to font rendering with 'cairo-
    dwrite' that could cause memory corruption leading to
    crashes and potentially code execution. (CVE-2012-0472)

  - An error exists in 'WebGLBuffer' that could lead to the
    reading of illegal video memory. (CVE-2012-0473)

  - An unspecified error could allow URL bar spoofing.
    (CVE-2012-0474)

  - IPv6 addresses and cross-site 'XHR' or 'WebSocket'
    connections on non-standard ports could allow this
    application to send ambiguous origin headers.
    (CVE-2012-0475)

  - A decoding issue exists related to 'ISO-2022-KR' and
    'ISO-2022-CN' character sets that could lead to cross-
    site scripting attacks. (CVE-2012-0477)

  - An error exists related to 'WebGL' and 'texImage2D'
    that could allow application crashes and possibly code
    execution when 'JSVAL_TO_OBJECT' is used on ordinary
    objects. (CVE-2012-0478)

  - Address bar spoofing is possible when 'Atom XML' or
    'RSS' data is loaded over HTTPS leading to phishing
    attacks. (CVE-2012-0479)"
  );
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2012-20/");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2012-22/");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2012-23/");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2012-24/");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2012-25/");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2012-26/");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2012-27/");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2012-28/");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2012-29/");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2012-30/");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2012-31/");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2012-32/");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2012-33/");
  script_set_attribute(attribute:"solution", value:"Upgrade to Firefox 12.0 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/04/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/04/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/04/27");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mozilla:firefox");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2012-2018 Tenable Network Security, Inc.");

  script_dependencies("mozilla_org_installed.nasl");
  script_require_keys("Mozilla/Firefox/Version");

  exit(0);
}

include("mozilla_version.inc");
port = get_kb_item_or_exit("SMB/transport");

installs = get_kb_list("SMB/Mozilla/Firefox/*");
if (isnull(installs)) audit(AUDIT_NOT_INST, "Firefox");

mozilla_check_version(installs:installs, product:'firefox', esr:FALSE, fix:'12.0', severity:SECURITY_HOLE, xss:TRUE);