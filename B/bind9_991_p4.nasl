#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(62562);
  script_version("1.11");
  script_cvs_date("Date: 2018/11/15 20:50:21");

  script_cve_id("CVE-2012-5166");
  script_bugtraq_id(55852);

  script_name(english:"ISC BIND 9 DNS RDATA Handling DoS");
  script_summary(english:"Checks version of BIND");

  script_set_attribute(attribute:"synopsis", value:
"The remote name server may be affected by a denial of service
vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the remote installation
of BIND can become locked up if certain combinations of RDATA are loaded
into the server. 
 
Note that Nessus has only relied on the version itself and has not
attempted to determine whether or not the install is actually
affected.");
  script_set_attribute(attribute:"see_also", value:"https://kb.isc.org/docs/aa-00801");
  script_set_attribute(attribute:"see_also", value:"http://ftp.isc.org/isc/bind9/9.6-ESV-R7-P4/CHANGES");
  script_set_attribute(attribute:"see_also", value:"http://ftp.isc.org/isc/bind9/9.7.6-P4/CHANGES");
  script_set_attribute(attribute:"see_also", value:"http://ftp.isc.org/isc/bind9/9.8.3-P4/CHANGES");
  script_set_attribute(attribute:"see_also", value:"http://ftp.isc.org/isc/bind9/9.9.1-P4/CHANGES");
  script_set_attribute(attribute:"solution", value:
"Upgrade to BIND 9.6-ESV-R7-P4 / 9.6-ESV-R8 / 9.7.6-P4 / 9.7.7 /
9.8.3-P4 / 9.8.4 / 9.9.1-P4 / 9.9.2 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2012-5166");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/10/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/10/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/10/16");

  script_set_attribute(attribute:"cpe", value:"cpe:/a:isc:bind");
  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"DNS");

  script_copyright(english:"This script is Copyright (C) 2012-2018 Tenable Network Security, Inc.");

  script_dependencies("bind_version.nasl");
  script_require_keys("bind/version", "Settings/ParanoidReport");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

if (report_paranoia < 2) audit(AUDIT_PARANOID);

ver = get_kb_item_or_exit("bind/version");

# Check whether BIND is vulnerable, and recommend an upgrade.
# Vuln 9.x >= 9.2 and 9.x < 9.6-ESV-R7-P4
fix = NULL;

if (ver =~ '^9\\.([2-5]($|[^0-9])|6(\\.|(-ESV($|-R([0-6]($|[^0-9])|7($|-P[0-3]($|[^0-9])))))))')
  fix = '9.6-ESV-R7-P4';
# Vuln 9.7.x < 9.7.6-P4
else if (ver =~ '^9\\.7\\.([0-5]($|[^0-9])|6($|-P[0-3]($|[^0-9])))')
  fix = '9.7.6-P4';
# Vuln 9.8.x < 9.8.3-P4
else if (ver =~ '^9\\.8\\.([0-2]($|[^0-9])|3($|-P[0-3]($|[^0-9])))')
  fix = '9.8.3-P4';
# Vuln 9.9.x < 9.9.1-P4
else if (ver =~ '^9\\.9\\.(0($|[^0-9])|1($|-P[0-3]($|[^0-9])))')
  fix = '9.9.1-P3';
else
  audit(AUDIT_LISTEN_NOT_VULN, "BIND", 53, ver, "UDP");

if (report_verbosity > 0)
{
  report =
    '\n  Installed version : ' + ver +
    '\n  Fixed version     : ' + fix +
    '\n';
  security_hole(port:53, proto:"udp", extra:report);
}
else security_hole(port:53, proto:"udp");
