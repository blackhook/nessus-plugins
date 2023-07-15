#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(120944);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2018-1786");
  script_bugtraq_id(105940);
  script_xref(name:"IAVA", value:"2019-A-0002");

  script_name(english:"IBM Spectrum Protect Client 7.1.x < 7.1.8.4 / 8.1.x < 8.1.6.1 Denial of Service Vulnerability (CVE-2018-1786)");

  script_set_attribute(attribute:"synopsis", value:
"The backup service installed on the remote host is affected by a
denial of service vulnerability.");
  script_set_attribute(attribute:"description", value:
"IBM Spectrum Protect, formerly known as Tivoli Storage Manager,
installed on the remote host is version 7.1.x < 7.1.8.4 or 8.1.x <
8.1.6.1. It is, therefore, affected by a denial of service (DoS)
vulnerability due to the incorrect accumulation of TCP/IP sockets in
a CLOSE_WAIT state. An unauthenticated, remote attacker can exploit
this issue to cause the process to stop responding.

Note that Nessus has not tested for this issue but has instead relied
only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"https://www-01.ibm.com/support/docview.wss?uid=ibm10738765");
  script_set_attribute(attribute:"solution", value:
"Upgrade to IBM Spectrum Protect 7.1.8.4 or 8.1.6.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-1786");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/11/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/11/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/01/03");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:tivoli_storage_manager");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/a:ibm:spectrum_protect");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"General");

  script_copyright(english:"This script is Copyright (C) 2019-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
  fix = "7.1.8.4";
else if (version =~ "^8\.1($|[^0-9])")
  fix = "8.1.6.1";
else
  audit(AUDIT_LISTEN_NOT_VULN, prod, port, version);

if (ver_compare(ver:version, fix:fix, strict:FALSE) < 0)
{
  report =
    '\n  Product           : ' + prod +
    '\n  Installed version : ' + version +
    '\n  Fixed version     : ' + fix +
    '\n';

  security_report_v4(port:port, severity:SECURITY_WARNING, extra:report);
}
else
  audit(AUDIT_LISTEN_NOT_VULN, prod, port, version);
