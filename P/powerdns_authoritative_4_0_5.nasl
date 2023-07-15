#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(106192);
  script_version("1.5");
  script_cvs_date("Date: 2019/11/08");

  script_cve_id("CVE-2017-15091");
  script_bugtraq_id(101982);

  script_name(english:"PowerDNS Authoritative < 4.0.5 Read Only Configuration Bypass (CVE-2017-15091)");
  script_summary(english:"Checks the PowerDNS Authoritative version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote name server is affected by a configuration bypass vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the version of the
PowerDNS Authoritative listening on the remote host is prior to
4.0.5. It is, therefore, affected by a vulnerability in the API where
a remote authenticated attacker can perform operations that affect the
server state even if the api-readonly configuration is enabled.

Note that Nessus has not attempted to exploit these issues but has
instead relied only on the application's self-reported version number.
Also, Nessus has not checked for the presence of the patch.");
  # https://doc.powerdns.com/authoritative/security-advisories/powerdns-advisory-2017-04.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d6d93a15");
  # https://blog.powerdns.com/2017/11/27/powerdns-authoritative-server-4-0-5-and-recursor-4-0-7-released/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?9ad28007");
  script_set_attribute(attribute:"see_also", value:"https://seclists.org/oss-sec/2017/q4/329");
  script_set_attribute(attribute:"solution", value:
"Upgrade to PowerDNS Authoritative 4.0.5 or later. Alternatively, apply the
patches referenced in the vendor advisories.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:L/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-15091");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/11/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/11/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/01/19");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:powerdns:powerdns");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:powerdns:authoritative");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"DNS");

  script_copyright(english:"This script is Copyright (C) 2018-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("pdns_version.nasl");
  script_require_keys("pdns/version_full", "pdns/version_source", "pdns/type", "Settings/ParanoidReport");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

app_name = "PowerDNS Authoritative";
version_source = get_kb_item_or_exit("pdns/version_source");
version = get_kb_item_or_exit("pdns/version_full");

port = 53;

# Only Authoritative is affected
type = get_kb_item_or_exit("pdns/type");
if (type != 'authoritative server') audit(AUDIT_NOT_LISTEN, app_name, port, "UDP");

if (version == "unknown") audit(AUDIT_UNKNOWN_APP_VER, app_name);
if (report_paranoia < 2) audit(AUDIT_PARANOID);

if (version =~ "^[0-3]\." || version =~ "^4\.0\.[0-4]([^0-9]|$)")
{
  report =
    '\n  Version source    : ' + version_source +
    '\n  Installed version : ' + version +
    '\n  Fixed version     : 4.0.5' +
    '\n';
  security_report_v4(severity:SECURITY_WARNING, port:port, proto:"udp", extra:report);
}
else
  audit(AUDIT_LISTEN_NOT_VULN, app_name, port, version, "UDP");
