#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(73475);
  script_version("1.3");
  script_cvs_date("Date: 2018/07/14  1:59:35");

  script_cve_id("CVE-2007-3114");
  script_bugtraq_id(24337);

  script_name(english:"MaraDNS 1.2.x < 1.2.12.05 / 1.3.x < 1.3.03 IPv6 Memory Leak Remote DoS");
  script_summary(english:"Checks version of MaraDNS server");

  script_set_attribute(attribute:"synopsis", value:
"The DNS server running on the remote host is affected by a denial of
service vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the MaraDNS server
running on the remote host is affected by a memory leak issue due to
improperly deallocating memory in the IPv6 code. This issue could
allow a remote attacker to cause a remote denial of service via memory
exhaustion by sending large amounts of invalid DNS packets.");
  script_set_attribute(attribute:"see_also", value:"http://maradns.samiam.org/security.html");
  # http://maradns.blogspot.com/2007/02/maradns-1303-released-hash-function.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?305f74d5");
  script_set_attribute(attribute:"see_also", value:"http://maradns.blogspot.com/2007/02/maradns-121205-released.html");
  script_set_attribute(attribute:"see_also", value:"http://osdir.com/ml/network.dns.maradns.general/2007-02/msg00000.html");
  script_set_attribute(attribute:"see_also", value:"http://maradns.samiam.org/changelog-2006-2010.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to MaraDNS version 1.2.12.05 / 1.3.03 or later or apply the
relevant patch.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(399);

  script_set_attribute(attribute:"vuln_publication_date", value:"2007/02/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2007/02/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/04/11");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:maradns:maradns");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"DNS");

  script_copyright(english:"This script is Copyright (C) 2014-2018 Tenable Network Security, Inc.");

  script_dependencies("maradns_version.nasl");
  script_require_keys("maradns/version", "maradns/num_ver", "Settings/ParanoidReport");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

version = get_kb_item_or_exit("maradns/version");
num_ver = get_kb_item_or_exit("maradns/num_ver");

if (report_paranoia < 2) audit(AUDIT_PARANOID);

port = 53;
fix = NULL;

# 1.2.x < 1.2.12.05
if (version =~ "^1\.2\." && ver_compare(ver:num_ver, fix:"1.2.12.05", strict:FALSE) == -1)
  fix = "1.2.12.05";

# 1.3.x < 1.3.03
else if (version =~ "^1\.3\." && ver_compare(ver:num_ver, fix:"1.3.03", strict:FALSE) == -1)
  fix = "1.3.03";

else
  audit(AUDIT_LISTEN_NOT_VULN, "MaraDNS", port, version, "UDP");


if (report_verbosity > 0)
{
  report =
    '\n  Installed version : ' + version +
    '\n  Fixed version     : ' + fix +
    '\n';
  security_warning(port:port, proto:"udp", extra:report);
}
else security_warning(port:port, proto:"udp");
