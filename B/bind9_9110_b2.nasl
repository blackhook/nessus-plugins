#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(106679);
  script_version("1.4");
  script_cvs_date("Date: 2018/06/29 12:00:59");

  script_cve_id("CVE-2016-6170");

  script_name(english:"ISC BIND Zone Data Denial of Service");
  script_summary(english:"Checks the version of BIND.");

  script_set_attribute(attribute:"synopsis", value:
"The remote name server is affected by a memory exhaustion
vulnerability");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the installation of
ISC BIND running on the remote name server is affected by a memory
exhaustion vulnerability. A server is potentially vulnerable if it
accepts zone data from another source, as no limit is currently
placed on zone data size.

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"https://kb.isc.org/article/AA-01390");
  script_set_attribute(attribute:"solution", value:
"Follow guidance provided by ISC advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  
  script_set_attribute(attribute:"vuln_publication_date", value:"2016/07/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/02/08");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:isc:bind");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"DNS");

  script_copyright(english:"This script is Copyright (C) 2018 Tenable Network Security, Inc.");

  script_dependencies("bind_version.nasl");
  script_require_keys("bind/version", "Settings/ParanoidReport");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

if (report_paranoia < 2) audit(AUDIT_PARANOID); 

ver = get_kb_item_or_exit("bind/version");

# Note that this is a protocol design error. It appears that ISC promised a
# fix for this, but their advisory seems to indicate that none has yet been
# released. However, we still rely on the "versions affected" data they provide
# since we don't have better information.

if (
  # 9.0.0 - 9.9.9-P2
  ver =~ "^9\.[0-9]\.[0-9]($|-P[1-2])" ||
  # 9.10.0 - 9.10.4-P1|P2
  ver =~ "^9\.10\.[0-4]($|-P[1-2])" ||
  # 9.11.0a1 - 9.11.0b2
  ver =~ "^9\.11\.0(a1|b2)$")
{
  report =
    '\n  Installed version : ' + ver +
    '\n';
  security_report_v4(severity:SECURITY_WARNING, port:53, extra:report);
  exit(0);
}

audit(AUDIT_LISTEN_NOT_VULN, "BIND", 53, ver);
