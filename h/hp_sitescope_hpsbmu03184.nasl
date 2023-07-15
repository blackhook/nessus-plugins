#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(79719);
  script_version("1.14");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/06/23");

  script_cve_id("CVE-2014-3566");
  script_bugtraq_id(70574);
  script_xref(name:"CERT", value:"577193");
  script_xref(name:"HP", value:"emr_na-c04497114");
  script_xref(name:"HP", value:"HPSBMU03184");
  script_xref(name:"HP", value:"SSRT101794");

  script_name(english:"HP SiteScope SSLv3 Padding Oracle On Downgraded Legacy Encryption Vulnerability (POODLE)");

  script_set_attribute(attribute:"synopsis", value:
"A web application installed on the remote host is affected by an
information disclosure vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of HP SiteScope installed on the remote host is affected
by a man-in-the-middle (MitM) information disclosure vulnerability
known as POODLE. The vulnerability is due to the way SSL 3.0 handles
padding bytes when decrypting messages encrypted using block ciphers
in cipher block chaining (CBC) mode. MitM attackers can decrypt a
selected byte of a cipher text in as few as 256 tries if they are able
to force a victim application to repeatedly send the same data over
newly created SSL 3.0 connections.");
  # https://cf.passport.softwaregrp.com/hppcf/login.do?hpappid=206728_SSO_PRO&TYPE=33554433&REALMOID=06-000a5aa8-5753-18f0-a414-00bd0f78a02e&GUID=&SMAUTHREASON=0&METHOD=GET&SMAGENTNAME=$SM$o8O1D10%2ftKElla5TtPp65rDrT5k5G0zxLqneTAG5uysO3%2f7yctjoO3h5%2fRpka45ewHx55dv9NlXXfizkUS%2fjPEDb6N%2fozvWQ&TARGET=$SM$https%3a%2f%2fsoftwaresupport.softwaregrp.com%2fgroup%2fsoftwaresupport%2fsearch-result%2f-%2ffacetsearch%2fdocument%2fKM01227923
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f1b8429f");
  # https://support.hpe.com/hpsc/doc/public/display?docId=emr_na-c04497114
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?4f254c1b");
  script_set_attribute(attribute:"see_also", value:"https://www.imperialviolet.org/2014/10/14/poodle.html");
  script_set_attribute(attribute:"see_also", value:"https://www.openssl.org/~bodo/ssl-poodle.pdf");
  script_set_attribute(attribute:"see_also", value:"https://tools.ietf.org/html/draft-ietf-tls-downgrade-scsv-00");
  script_set_attribute(attribute:"solution", value:
"Refer to the instructions in vendor support document KM01227923 for
steps to disable SSLv3.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:R/S:C/C:L/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2014-3566");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"in_the_news", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/10/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/11/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/12/04");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:hp:sitescope");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2014-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("hp_sitescope_detect.nasl", "ssl_poodle.nasl");
  script_require_keys("www/sitescope");
  script_require_ports("Services/www", 8080);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("webapp_func.inc");
include("http.inc");

port = get_http_port(default:8080);

install = get_install_from_kb(appname:'sitescope', port:port, exit_on_fail:TRUE);
version = install['ver'];
dir     = install['dir'];
vuln    = FALSE;

if (version == UNKNOWN_VER) audit(AUDIT_UNKNOWN_WEB_APP_VER, 'HP SiteScope', build_url(port:port, qs:dir));

if (version =~ "^11\.[12]\d($|[^0-9])")
{
  vuln = TRUE;
  # If not paranoid, do not report if not
  # vuln to real POODLE check
  if (report_paranoia < 2 && !get_kb_item("SSL/vulnerable_to_poodle/"+port))
    vuln = FALSE;
}

if (vuln)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  URL               : ' + build_url(port:port, qs:dir) +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : See solution.' +
      '\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
  exit(0);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, 'HP SiteScope',  build_url(port:port, qs:dir), version);
