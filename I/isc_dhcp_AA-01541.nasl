#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(106202);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/10/25");

  script_cve_id("CVE-2017-3144");
  script_bugtraq_id(102726);

  script_name(english:"ISC DHCP 4.1.0 to 4.1-ESV-R15 / 4.2.0 to 4.2.8 / 4.3.0 to 4.3.6 DoS vulnerability");
  script_summary(english:"Checks the DHCP server version.");

  script_set_attribute(attribute:"synopsis", value:
"The DHCP server installed on the remote Linux host is affected by a
denial of service vulnerability.");
  script_set_attribute(attribute:"description", value:
"The DHCP server version installed on the remote host is
4.1.0 to 4.1-ESV-R15, 4.2.0 to 4.2.8, or 4.3.0 to 4.3.6. It is,
therefore, vulnerable to a denial of service condition with in the
omapi_connection_writer() function of the omapip/buffer.c script
due to improper handling of an empty message. A local attacker could
potentially exhaust the available descriptors.");
  script_set_attribute(attribute:"see_also", value:"https://kb.isc.org/article/AA-01541");
  script_set_attribute(attribute:"solution", value:
"Please refer to the vendor's advisory.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-3144");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/12/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/01/19");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:isc:dhcp");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2018-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("dhcp_detect.nbin");
  script_require_keys("dhcp_server/type", "dhcp_server/version", "Settings/ParanoidReport");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

app = "ISC DHCP";

type = get_kb_item_or_exit("dhcp_server/type");

if (isc-dhcp >!< type) audit(AUDIT_NOT_INST, app);

version = get_kb_item_or_exit("dhcp_server/version");

if (version !~ "^4\.[234]($|\.[0-9.]+)")
  audit(AUDIT_INST_VER_NOT_VULN, app, version);

if (version =~ "^[0-9]+\.[0-9]+$")
  audit(AUDIT_VER_NOT_GRANULAR, app, version);

if (report_paranoia < 2) audit(AUDIT_PARANOID);

if (version =~ "^4\.1\.")
{
  min = '4.1.0';
  max = '4.1.9999.15';
}
else if (version =~ "^4\.2\.")
{
  min = '4.2.0';
  max = '4.2.8';
}
else if (version =~ "^4\.3\.")
{
  min = '4.3.0';
  max = '4.3.6';
}

if ((ver_compare(fix:min, ver:version, strict:FALSE) >= 0) &&
    (ver_compare(fix:max, ver:version, strict:FALSE) <= 0))
{
  report = '\n  Installed version : ' + version + '\n';
  security_report_v4(severity:SECURITY_WARNING, port:0, extra:report);
}
else audit(AUDIT_INST_VER_NOT_VULN, app, version);
