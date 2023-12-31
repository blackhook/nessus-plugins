#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(83529);
  script_version("1.4");
  script_cvs_date("Date: 2019/11/22");

  script_cve_id("CVE-2015-3455");
  script_bugtraq_id(74438);

  script_name(english:"Squid 3.2 < 3.5.4 Incorrect X509 Server Certificate Validation Vulnerability");
  script_summary(english:"Checks the version of Squid.");

  script_set_attribute(attribute:"synopsis", value:
"The remote proxy server may be affected by a certificate validation
vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its banner, the version of Squid running on the remote
host is 3.2 prior to 3.2.14 / 3.3.14 / 3.4.13 / 3.5.4. It is,
therefore, potentially affected by a flaw related to certificate
validation due to the server hostname not being verified as matching a
the domain name in the certificate Subject's Common Name (CN) or the
SubjectAltName fields. A man-in-the-middle attacker, using a crafted
certificate, can utilize this to spoof a TLS/SSL server, thus allowing
the disclosure or manipulation of intercepted data. Note that this
flaw is exploitable only if Squid is configured to perform SSL Bumping
with the 'client-first' or 'bump' mode of operation.

Note that Nessus has not tested for this issue but has instead relied
only on the application's self-reported version number. The patch
released to address the issue does not update the version in the
banner. If the patch has been applied properly, and the service has
been restarted, consider this to be a false positive.");
  script_set_attribute(attribute:"see_also", value:"http://www.squid-cache.org/Advisories/");
  script_set_attribute(attribute:"see_also", value:"http://www.squid-cache.org/Advisories/SQUID-2015_1.txt");
  # http://www.squid-cache.org/Versions/v3/3.5/changesets/SQUID_3_5_4.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?8ef2aa9b");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Squid versions 3.2.14 / 3.3.14 / 3.4.13 / 3.5.4, or apply
the vendor-supplied patch.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2015-3455");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/05/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/05/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/05/19");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:squid-cache:squid");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Firewalls");

  script_copyright(english:"This script is Copyright (C) 2015-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("squid_version.nasl");
  script_require_keys("www/squid", "Settings/ParanoidReport");
  script_require_ports("Services/http_proxy", 3128, 8080);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

# Build a list of ports from the
list = get_kb_list("http_proxy/*/squid/version");
if (isnull(list)) audit(AUDIT_NOT_INST, "Squid");

# nb: banner checks of open source software are prone to false-
#     positives so only run the check if reporting is paranoid.
if (report_paranoia < 2) audit(AUDIT_PARANOID);

vulnerable = FALSE;
not_vuln_list = make_list();

foreach item (keys(list))
{
  port = ereg_replace(pattern:'^http_proxy/([0-9]+)/squid/version', replace:'\\1', string:item);
  version = list[item];

  # regexp checked using kb file
  if (
    # version 3.2
    version =~ "^3\.2([^\.0-9]|$)" ||
    # version 3.2.1-13
    version =~ "^3\.2\.([0-9]|1[0-3])([^0-9]|$)" ||
    # version 3.3
    version =~ "^3\.3([^\.0-9]|$)" ||
    # version 3.3.1-13
    version =~ "^3\.3\.([0-9]|1[0-3])([^0-9]|$)" ||
    # version 3.4
    version =~ "^3\.4([^\.0-9]|$)" ||
    # version 3.4.1-12
    version =~ "^3\.4\.([0-9]|1[0-2])([^0-9]|$)" ||
    # version 3.5
    version =~ "^3\.5([^\.0-9]|$)" ||
    # version 3.5.1-3
    version =~ "^3\.5\.([0-3])([^0-9]|$)" 
  )
  {
    vulnerable = TRUE;
    if (report_verbosity > 0)
    {
      source = get_kb_item('http_proxy/'+port+'/squid/source');
      report =
        '\n  Version source    : ' + source +
        '\n  Installed version : ' + version +
        '\n  Fixed versions    : 3.5.4, 3.4.13, 3.3.14, and 3.2.14' +
        '\n';
      security_note(port:port, extra:report);
    }
    else security_note(port);
  }
  else not_vuln_list = make_list(not_vuln_list, version + " on port " + port);
}

if (vulnerable) exit(0);
else
{
  installs = max_index(not_vuln_list);
  if (installs == 0) audit(AUDIT_NOT_INST, "Squid");
  else if (installs == 1)
    audit(AUDIT_INST_VER_NOT_VULN, "Squid", not_vuln_list[0]);
  else
    exit(0, "The Squid installs ("+ join(not_vuln_list, sep:", ") + ") are not affected.");
}
