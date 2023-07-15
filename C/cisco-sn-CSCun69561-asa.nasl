#TRUSTED 4823c761de5c59fd26e4f08df13fa28a67c70d0aa8ae725b755988ae73afe8dc71870130528ef1dfcd8146662628f7756762b76e6b9c3e34cebb126d7ffec2ef8178b8ee132badb09c43dbb037b9805e1af15e5a6367c68a14ee4d649359451fac96b2311d97a2e0cd5636fdec3b2045511aedf90d189fae5497ec9fed827e3166f6c9cc5dfa4c5cb8daa9b775c7d4a5716a02eb3d2647ab7b680e661810af8c2ca9c351172b91b72287a58f47714503d7de8adf54626a16fcdc606dd929139ebec624e79ae58089eaf0c3c52517096dcc586f6567df8be8446e9360f61761e888c80fdc0000c3f0a21cbfcbf43da9e17ebc4f215a5f31f4a7766573d423f8905269616fabbe89762d4d6298592a53defa39e50225b56401ad0fa5c03ffb35f17231ee27cf0c284fd17579759538f9ad0d07fdb9a274856a2be0e473573469de4d766d856bae3e86d153e9b6c521490c2ae3d603ccb7cb9fe95920e4f669672b6c77e052d9a14c374de63cb11d6d665cae8478e30406520c975df819c92f5f9575f8a286cfcf3962cc19753c0435e28f7c20ecc3d136145fd1f60e498b5744e130063989514dbcbf6e1bba74a2f92c1d45ed5d4e7d9fe1cdcb740cf5b9d7a0cf97eac9c5854868a95c27fd3e61030c69ab539eaa90c5fa22ae6cfe67dcef4be1cf5de19dd3e41ed3c751c1ab32f1caaa5f9422b8a7ac85dc22aa6fd23816ed3d
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(74443);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2018/11/15");

  script_cve_id("CVE-2014-3264");
  script_bugtraq_id(67547);
  script_xref(name:"CISCO-BUG-ID", value:"CSCun69561");

  script_name(english:"Cisco ASA RADIUS radius_rcv_auth DoS (CSCun69561)");
  script_summary(english:"Checks ASA version");

  script_set_attribute(attribute:"synopsis", value:"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its banner, the version of the remote Cisco ASA device is
affected by a denial of service vulnerability due to improper
validation of RADIUS packets. A remote attacker that knows the RADIUS
shared secret could cause a denial of service by injecting a specially
crafted packet during a RADIUS authentication exchange.");
  # https://tools.cisco.com/security/center/viewAlert.x?alertId=34273
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?92bacc20");
  # https://tools.cisco.com/security/center/viewAlert.x?alertId=34273
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?92bacc20");
  script_set_attribute(attribute:"solution", value:"Apply the relevant patch referenced in Cisco Bug Id CSCun69561.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:adaptive_security_appliance_software");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/05/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/05/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/06/11");

  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2018 Tenable Network Security, Inc.");
  script_family(english:"CISCO");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/Cisco/ASA", "Host/Cisco/ASA/model");

  exit(0);
}

include("audit.inc");
include("cisco_func.inc");
include("cisco_kb_cmd_func.inc");

asa   = get_kb_item_or_exit('Host/Cisco/ASA');
model = get_kb_item_or_exit('Host/Cisco/ASA/model');

ver = extract_asa_version(asa);
if (isnull(ver)) audit(AUDIT_FN_FAIL, 'extract_asa_version');

if (model !~ '^55[0-9][0-9](|-)X($|[^0-9])') audit(AUDIT_HOST_NOT, 'ASA 5500-X series');

fixed_ver = NULL;

if (ver =~ "^8\.[46][^0-9]")
  fixed_ver = "Refer to the vendor for a fix.";

else if (ver =~ "^9\.0[^0-9]" && check_asa_release(version:ver, patched:"9.0(4.8)"))
  fixed_ver = "9.0(4)8";

else if (ver =~ "^9\.1[^0-9]" && check_asa_release(version:ver, patched:"9.1(5.1)"))
  fixed_ver = "9.1(5)1";

else if (ver =~ "^9\.2[^0-9]" && check_asa_release(version:ver, patched:"9.2(1.1)"))
  fixed_ver = "9.2(1)1";

else
  audit(AUDIT_INST_VER_NOT_VULN, "Cisco ASA software", ver);

override = FALSE;

# Check if RADIUS authentication is enabled
if (get_kb_item("Host/local_checks_enabled"))
{
  flag = FALSE;

  buf = cisco_command_kb_item("Host/Cisco/Config/show_running-config", "show running-config");
  if (check_cisco_result(buf))
  {
    if (preg(multiline:TRUE, pattern:"aaa-server \S+ protocol radius", string:buf)) flag = TRUE;
  }
  else if (cisco_needs_enable(buf)) override = TRUE;

  if (!flag && !override) audit(AUDIT_HOST_NOT, "affected because RADIUS is not enabled.");
}

if (report_verbosity > 0)
{
  report =
    '\n  Installed version : ' + ver +
    '\n  Fixed version     : ' + fixed_ver +
    '\n';
  security_warning(port:0, extra:report+cisco_caveat(override));
}
else security_warning(port:0, extra:cisco_caveat(override));
