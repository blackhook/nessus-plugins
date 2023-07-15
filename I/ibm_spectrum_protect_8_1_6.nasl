#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(118823);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2018-1788");
  script_bugtraq_id(105818);
  script_xref(name:"IAVB", value:"2018-B-0141-S");

  script_name(english:"IBM Spectrum Protect Server 7.1.x < 7.1.9.100 / 8.1.x < 8.1.6 Information Disclosure Vulnerability");

  script_set_attribute(attribute:"synopsis", value:
"The backup service installed on the remote host is affected by an
information disclosure vulnerability.");
  script_set_attribute(attribute:"description", value:
"IBM Spectrum Protect, formerly known as Tivoli Storage Manager,
installed on the remote host is version 7.1.x < 7.1.9.100 or 8.1.x <
8.1.6. It is, therefore, affected by an information disclosure
vulnerability.

Note that Nessus has not tested for this issue but has instead relied
only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"https://www-01.ibm.com/support/docview.wss?uid=ibm10730357");
  script_set_attribute(attribute:"solution", value:
"Upgrade to IBM Spectrum Protect Server 7.1.9.100 or 8.1.6 or later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:H/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-1788");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/10/31");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/10/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/11/08");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:tivoli_storage_manager");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/a:ibm:spectrum_protect");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"General");

  script_copyright(english:"This script is Copyright (C) 2018-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ibm_tsm_detect.nasl");
  script_require_keys("installed_sw/IBM Tivoli Storage Manager");
  script_require_ports("Services/tsm-agent");

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("audit.inc");
include("install_func.inc");

port    = get_service(svc:"tsm-agent",exit_on_fail:TRUE);
prod    = "IBM Tivoli Storage Manager";
install = get_single_install(app_name:prod, port:port, exit_if_unknown_ver:TRUE);

version = install["version"];

# Starting with 7.1.3, IBM TSM is known as IBM Spectrum Protect
if (ver_compare(ver:version, fix:"7.1.3.0", strict:FALSE) >= 0)
  prod = "IBM Spectrum Protect";

if (version =~ "^7\.1($|[^0-9])")
  fix = "7.1.9.100";
else if (version =~ "^8\.1($|[^0-9])")
  fix = "8.1.6";
else
  audit(AUDIT_LISTEN_NOT_VULN, prod, port, version);

if (ver_compare(ver:version, fix:fix, strict:FALSE) < 0)
{
  report =
    '\n  Product           : ' + prod +
    '\n  Installed version : ' + version +
    '\n  Fixed version     : ' + fix +
    '\n';

  security_report_v4(port:port, severity:SECURITY_NOTE, extra:report);
}
else
  audit(AUDIT_LISTEN_NOT_VULN, prod, port, version);
