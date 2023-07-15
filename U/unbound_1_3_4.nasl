#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(106379);
  script_version("1.5");
  script_cvs_date("Date: 2018/11/15 20:50:21");

  script_cve_id("CVE-2009-3602");
  script_bugtraq_id(37459);

  script_name(english:"Unbound < 1.3.4 NSEC3 Signature Verification DNS Spoofing Vulnerability (CVE-2009-3602)");
  script_summary(english:"Checks version of Unbound");

  script_set_attribute(attribute:"synopsis", value:
"The remote name server is affected by a remote DNS spoofing
vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the remote Unbound DNS
resolver is affected by a remote DNS spoofing vulnerability when
verifying NSEC3 signatures.");
  script_set_attribute(attribute:"see_also", value:"https://nlnetlabs.nl/projects/unbound/download/");

  script_set_attribute(attribute:"solution", value:"Upgrade to Unbound version 1.3.4 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(310);

  script_set_attribute(attribute:"vuln_publication_date", value:"2009/10/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2009/10/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/01/26");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:unbound:unbound");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"DNS");

  script_copyright(english:"This script is Copyright (C) 2018 Tenable Network Security, Inc.");

  script_dependencies("unbound_version.nasl");
  script_require_keys("Settings/ParanoidReport","unbound/version");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

version = get_kb_item_or_exit("unbound/version");
if (report_paranoia < 2) audit(AUDIT_PARANOID);

fixed_version = "1.3.4";
port = 53;

tcp = get_kb_item("DNS/tcp/53");
if (!isnull(tcp)) proto = "tcp";
else proto = "udp"; # default

# if version < 1.3.4 (including patches and rc)
if (
  version =~ "^0\." ||
  version =~ "^1\.[0-2]($|[^0-9])" ||
  version =~ "^1\.3(\.[0-3](\.[0-9]+)*)?(([abp]|rc)[0-9]*)?$" ||
  version =~ "^1\.3\.4([ab]|rc)[0-9]*$"
)
{
  report =
    '\n  Installed version : ' + version +
    '\n  Fixed version     : ' + fixed_version +
    '\n';
  security_report_v4(severity:SECURITY_HOLE, port:port, proto:proto, extra:report);
}
else audit(AUDIT_LISTEN_NOT_VULN, "Unbound", port, version);
