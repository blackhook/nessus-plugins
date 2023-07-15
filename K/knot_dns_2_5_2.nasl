#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(106196);
  script_version("1.4");
  script_cvs_date("Date: 2018/07/13 15:08:46");

  script_cve_id("CVE-2017-11104");
  script_bugtraq_id(99598);

  script_name(english:"Knot DNS 2.4.x < 2.4.4 / 2.5.x < 2.5.2 TSIG Authentication Bypass Vulnerability (CVE-2017-11104)");
  script_summary(english:"Checks the version of Knot DNS.");

  script_set_attribute(attribute:"synopsis", value:
"The remote DNS server is affected by an authentication bypass
vulnerability.");
  script_set_attribute(attribute:"description", value:
"The Knot DNS server running on the remote host is version 2.4.x prior
to 2.4.5 or 2.5.x prior to 2.5.2. It is, therefore, affected by a TSIG
authentication bypass vulnerability.");
  script_set_attribute(attribute:"see_also", value:"https://gitlab.labs.nic.cz/knot/knot-dns/raw/v2.4.5/NEWS");
  script_set_attribute(attribute:"see_also", value:"https://gitlab.labs.nic.cz/knot/knot-dns/raw/v2.5.2/NEWS");
  # https://lists.nic.cz/pipermail/knot-dns-users/2017-June/001144.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?42ae186b");
  # https://www.synacktiv.com/ressources/Knot_DNS_TSIG_Signature_Forgery.pdf
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?8ee559d2");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Knot DNS version 2.4.5 / 2.5.2 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/06/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/06/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/01/19");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/a:cz.nic:knot_dns");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"DNS");

  script_copyright(english:"This script is Copyright (C) 2018 Tenable Network Security, Inc.");

  script_dependencies("knot_dns_version.nasl");
  script_require_keys("knot_dns/proto", "Settings/ParanoidReport");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

proto = get_kb_item("knot_dns/proto");

port = 53;
version = get_kb_item_or_exit("knot_dns/"+proto+"/version");

if (version =~ "^2(\.[45])?$")
  audit(AUDIT_VER_NOT_GRANULAR, "Knot DNS", port, version);

if (report_paranoia < 2) audit(AUDIT_PARANOID);

if (version =~ "^2\.(4\.[0-4]|5\.[01])($|[^0-9])")
{
  report =
    '\n  Installed version : ' + version +
    '\n  Fixed version     : 2.4.5 / 2.5.2' +
    '\n';
  security_report_v4(severity:SECURITY_WARNING, port:port, proto:tolower(proto), extra:report);
}
else audit(AUDIT_LISTEN_NOT_VULN, "Knot DNS", port, version, proto);
