#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(74288);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/10/15");

  script_cve_id("CVE-2014-0076", "CVE-2014-0963");
  script_bugtraq_id(66363, 67238);

  script_name(english:"IBM Global Security Kit 7 < 7.0.4.50 / 8.0.14.x < 8.0.14.43 / 8.0.50.x < 8.0.50.20 Multiple Vulnerabilities (Linux)");
  script_summary(english:"Checks GSKit version");

  script_set_attribute(attribute:"synopsis", value:
"The remote Linux host has a library installed that is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote Linux host has a version of IBM Global Security Kit prior
to 7.0.4.50 / 8.0.14.43 / 8.0.50.20. It is, therefore, affected by the
following vulnerabilities :

  - An error exists related to the implementation of the
    Elliptic Curve Digital Signature Algorithm (ECDSA) that
    could allow nonce disclosure via the 'FLUSH+RELOAD'
    cache side-channel attack. (CVE-2014-0076)

  - A denial of service vulnerability exists which an
    attacker can exploit by sending a specially crafted SSL
    request to cause the host to become unresponsive.
    (CVE-2014-0963)");
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg21672189");
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg21672950");
  script_set_attribute(attribute:"see_also", value:"https://www-304.ibm.com/support/docview.wss?uid=swg21672843");
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg21671919");
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg21673521");
  script_set_attribute(attribute:"see_also", value:"https://www-304.ibm.com/support/docview.wss?uid=swg21672843");
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg21673682");
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg21672192");
  script_set_attribute(attribute:"see_also", value:"https://www-304.ibm.com/support/docview.wss?uid=swg21673749");
  script_set_attribute(attribute:"see_also", value:"https://www-304.ibm.com/support/docview.wss?uid=swg21673745");
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg21673418");
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg21671732");
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg21673282");
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg21672192");
  script_set_attribute(attribute:"see_also", value:"https://www-304.ibm.com/support/docview.wss?uid=swg21673259");
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg21673696");
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg21673245");
  script_set_attribute(attribute:"see_also", value:"https://www-304.ibm.com/support/docview.wss?uid=swg21673689");
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg21673600");
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg21672869");
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg21673717");
  script_set_attribute(attribute:"see_also", value:"https://www-304.ibm.com/support/docview.wss?uid=swg21673666");
  script_set_attribute(attribute:"see_also", value:"https://www-304.ibm.com/support/docview.wss?uid=swg21673008");
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg21672724");
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg21673040");
  script_set_attribute(attribute:"solution", value:
"Apply GSKit 7.0.4.50 / 8.0.14.43 / 8.0.50.20 or later or apply the
appropriate patch referenced in the advisory.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2014-0076");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/02/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/05/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/06/03");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:global_security_kit");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"General");

  script_copyright(english:"This script is Copyright (C) 2014-2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ibm_gskit_installed_nix.nbin");
  script_require_keys("installed_sw/IBM GSKit", "Settings/ParanoidReport");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("install_func.inc");

if (report_paranoia < 2) audit(AUDIT_PARANOID);

if (get_kb_item("SMB/Registry/Enumerated")) audit(AUDIT_OS_NOT, "Linux", "Windows");

app = "IBM GSKit";
install = get_single_install(app_name:app, exit_if_unknown_ver:TRUE);

version = install['version'];
path = install['path'];
fix = NULL;

if (version =~ '^7\\.0\\.' && ver_compare(ver:version, fix:'7.0.4.50') < 0)
  fix = '7.0.4.50';
else if (version =~ '^8\\.0\\.14\\.' && ver_compare(ver:version, fix:'8.0.14.43') < 0)
  fix = '8.0.14.43';
else if (version =~ '^8\\.0\\.50\\.' && ver_compare(ver:version, fix:'8.0.50.20') < 0)
  fix = '8.0.50.20';
else
  audit(AUDIT_INST_PATH_NOT_VULN, app, version, path);

if (report_verbosity > 0)
{
  report =
  '\n  Path              : ' + path +
  '\n  Installed version : ' + version +
  '\n  Fixed version     : ' + fix + '\n';

  security_note(port:0, extra:report);
}
else security_note(0);
