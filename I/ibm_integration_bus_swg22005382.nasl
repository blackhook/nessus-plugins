#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(101521);
  script_version("1.6");
  script_cvs_date("Date: 2019/11/12");

  script_cve_id("CVE-2017-1144", "CVE-2017-1207");
  script_bugtraq_id(99365, 99368);

  script_name(english:"IBM Integration Bus 8.x < 8.0.0.9 / 9.x < 9.0.0.8 / 10.x < 10.0.0.8 Multiple Vulnerabilities");
  script_summary(english:"Checks the version of IBM Integration Bus.");

  script_set_attribute(attribute:"synopsis", value:
"An enterprise service bus application installed on the remote host is
affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of IBM Integration Bus (formerly known as IBM WebSphere
Message Broker) installed on the remote host is 8.x prior to 8.0.0.9,
9.x prior to 9.0.0.8, or 10.x prior to 10.0.0.8. It is, therefore,
affected by multiple vulnerabilities :

  - A denial of service vulnerability exists due to the use
    of an unquoted search path that allows a local attacker
    with specialized access to prevent the message broker
    from starting. (CVE-2017-1144)

  - An information disclosure vulnerability exists in the
    service trace component due to logging passwords in
    plaintext. A local attacker can exploit this to disclose
    web user passwords. (CVE-2017-1207)");
  script_set_attribute(attribute:"see_also", value:"https://www-01.ibm.com/support/docview.wss?uid=swg22005382");
  script_set_attribute(attribute:"see_also", value:"https://www-01.ibm.com/support/docview.wss?uid=swg22005383");
  script_set_attribute(attribute:"solution", value:
"Upgrade to IBM Integration Bus version 8.0.0.9 / 9.0.0.8 / 10.0.0.8 or
later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-1207");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/06/30");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/06/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/07/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:websphere_message_broker");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:integration_bus");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2017-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ibm_integration_bus_installed.nbin");
  script_require_keys("installed_sw/IBM Integration Bus");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("install_func.inc");

app = 'IBM Integration Bus';
get_install_count(app_name:app, exit_if_zero:TRUE);

install = get_single_install(app_name: app, exit_if_unknown_ver: TRUE);

path = install['path'];
version = install['version'];

if (version =~ "^10\.")
  fix = "10.0.0.8";
else if (version =~ "^9\.")
  fix = "9.0.0.8";
else if (version =~ "^8\.")
  fix = "8.0.0.9";
else
  audit(AUDIT_INST_PATH_NOT_VULN, app, version, path);

if (ver_compare(ver:version, fix:fix, strict:FALSE) >= 0)
  audit(AUDIT_INST_PATH_NOT_VULN, app, version, path);

port = get_kb_item("SMB/transport");
if (!port) port = 445;

order = make_list("Installed version", "Fixed version", "Path");
report = make_array(
  order[0], version,
  order[1], fix,
  order[2], path
);
report = report_items_str(report_items:report, ordered_fields:order);

security_report_v4(port:port, extra:report, severity:SECURITY_NOTE);
