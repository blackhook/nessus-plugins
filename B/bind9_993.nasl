#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(106136);
  script_version("1.5");
  script_cvs_date("Date: 2019/11/08");

  script_cve_id("CVE-2012-5689");
  script_bugtraq_id(57556);

  script_name(english:"ISC BIND 9 DNS64 Handling DoS (CVE-2012-5689)");
  script_summary(english:"Checks version of BIND");

  script_set_attribute(attribute:"synopsis", value:
"The remote name server is prone to a denial of service attack.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the remote installation
of BIND can be forced to crash via maliciously crafted DNS requests. 

Note that this vulnerability only affects installs using the 'dns64'
configuration option. 
 
Further note that Nessus has only relied on the version itself and has
not attempted to determine whether or not the install is actually
affected.");
  script_set_attribute(attribute:"see_also", value:"https://kb.isc.org/docs/aa-00855");
  script_set_attribute(attribute:"see_also", value:"http://ftp.isc.org/isc/bind9/9.8.5/CHANGES");
  script_set_attribute(attribute:"see_also", value:"http://ftp.isc.org/isc/bind9/9.9.3/CHANGES");
  script_set_attribute(attribute:"solution", value:
"Upgrade to BIND 9.8.5 / 9.9.3 or later.  Alternatively, disable
DNS64 functionality via configuration options.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2012-5689");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/01/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/05/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/01/18");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:isc:bind");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"DNS");

  script_copyright(english:"This script is Copyright (C) 2018-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
# Vuln 9.8.0 < 9.8.5 and 9.9.0 < 9.9.3
fix = NULL;

# Vuln 9.8.0 < 9.8.5
if (ver =~ "^9\.8\.[0-4]($|[^0-9])")
  fix = '9.8.5';
# Vuln 9.9.0 < 9.9.3
else if (ver =~ "^9\.9\.[0-2]($|[^0-9])")
  fix = '9.9.3';
else
  audit(AUDIT_LISTEN_NOT_VULN, "BIND", 53, ver, "UDP");

items = make_array(
  "Installed version", ver,
  "Fixed version", fix
);
order = make_list("Installed version", "Fixed version");
security_report_v4(
  severity:SECURITY_HOLE,
  port:53,
  proto:"udp",
  extra:report_items_str(
    report_items:items,
    ordered_fields:order
  )
);
