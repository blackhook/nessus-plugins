#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(61413);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/05");

  script_cve_id("CVE-2011-3389", "CVE-2012-3698");
  script_bugtraq_id(49778, 54679);
  script_xref(name:"CERT", value:"864643");
  script_xref(name:"CEA-ID", value:"CEA-2019-0547");

  script_name(english:"Apple Xcode < 4.4 Multiple Vulnerabilities (Mac OS X) (BEAST)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has an application installed that is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote Mac OS X host has a version of Apple Xcode installed that is prior to 4.4. It is, therefore, affected by
multiple vulnerabilities :

  - An information disclosure vulnerability, known as BEAST, exists in the SSL 3.0 and TLS 1.0 protocols due
    to a flaw in the way the initialization vector (IV) is selected when operating in cipher-block chaining
    (CBC) modes. A man-in-the-middle attacker can exploit this to obtain plaintext HTTP header data, by using
    a blockwise chosen-boundary attack (BCBA) on an HTTPS session, in conjunction with JavaScript code that
    uses the HTML5 WebSocket API, the Java URLConnection API, or the Silverlight WebClient API.
    (CVE-2011-3389)

  - An information disclosure vulnerability exists that may allow a specially crafted App Store application to
    read entries in the keychain. (CVE-2012-3698)");
  script_set_attribute(attribute:"see_also", value:"http://support.apple.com/kb/HT5416");
  script_set_attribute(attribute:"see_also", value:"http://lists.apple.com/archives/security-announce/2012/Jul/msg00001.html");
  script_set_attribute(attribute:"see_also", value:"https://www.imperialviolet.org/2011/09/23/chromeandbeast.html");
  script_set_attribute(attribute:"see_also", value:"https://www.openssl.org/~bodo/tls-cbc.txt");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Apple Xcode version 4.4 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2012-3698");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"in_the_news", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/07/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/07/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/08/03");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apple:xcode");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2012-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("macosx_xcode_installed.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/MacOSX/Version", "installed_sw/Apple Xcode");

  exit(0);
}

include('vcf.inc');

get_kb_item_or_exit('Host/local_checks_enabled');

os = get_kb_item('Host/MacOSX/Version');
if (empty_or_null(os))
  audit(AUDIT_OS_NOT, 'macOS or Mac OS X');

app_info = vcf::get_app_info(app:'Apple Xcode');

vcf::check_granularity(app_info:app_info, sig_segments:2);

constraints = [
  { 'fixed_version' : '4.4' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
