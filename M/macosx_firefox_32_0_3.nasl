#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(77901);
  script_version("1.8");
  script_cvs_date("Date: 2019/11/25");

  script_cve_id("CVE-2014-1568");
  script_bugtraq_id(70116);
  script_xref(name:"CERT", value:"772676");

  script_name(english:"Firefox < 32.0.3 NSS Signature Verification Vulnerability (Mac OS X)");
  script_summary(english:"Checks the version of Firefox.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Mac OS X host contains a web browser that is affected by a
signature forgery vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Firefox installed on the remote host is prior to
32.0.3. It is, therefore, affected by a flaw in the Network Security
Services (NSS) library, which is due to lenient parsing of ASN.1
values involved in a signature and can lead to the forgery of RSA
signatures, such as SSL certificates.");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/security/announce/2014/mfsa2014-73.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Firefox 32.0.3 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2014-1568");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/09/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/09/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/09/26");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mozilla:firefox");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2014-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("macosx_firefox_installed.nasl");
  script_require_keys("MacOSX/Firefox/Installed");

  exit(0);
}

include("mozilla_version.inc");

kb_base = "MacOSX/Firefox";
get_kb_item_or_exit(kb_base+"/Installed");

version = get_kb_item_or_exit(kb_base+"/Version", exit_code:1);
path = get_kb_item_or_exit(kb_base+"/Path", exit_code:1);

if (get_kb_item(kb_base + '/is_esr')) exit(0, 'The Mozilla Firefox installation is in the ESR branch.');

mozilla_check_version(product:'firefox', version:version, path:path, esr:FALSE, fix:'32.0.3', severity:SECURITY_HOLE, xss:FALSE);
