#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(92558);
  script_version("1.16");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/10/09");

  script_cve_id("CVE-2016-0739", "CVE-2016-0787", "CVE-2016-4802");
  script_bugtraq_id(83186, 83389, 90997);

  script_name(english:"Tenable SecurityCenter < 5.4.0 Multiple Vulnerabilities (TNS-2016-12)");
  script_summary(english:"Checks the SecurityCenter version.");

  script_set_attribute(attribute:"synopsis", value:
"An application installed on the remote host is affected by multiple
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the Tenable SecurityCenter
application installed on the remote host is prior to 5.4.0. It is,
therefore, affected by multiple vulnerabilities :

  - An arbitrary code execution vulnerability exists in the
    bundled version of libcurl due to using an insecure path
    to look for specific libraries, including the current
    working directory, which may not be under user control.
    A remote attacker can exploit this to inject and execute
    arbitrary code in the context of the current user.
    (CVE-2016-4802)

  - Multiple flaws exist in the bundled version of libssh
    due to a failure to securely generate Diffie-Hellman
    secret keys. A man-in-the-middle attacker can exploit
    these flaws to intercept and decrypt SSH sessions.
    (CVE-2016-0739, CVE-2016-0787)

  - An integer overflow condition exists in the bundled
    version of libcurl due to improper validation of
    user-supplied input when handling 'timeval'. An attacker
    can exploit this to have an unspecified impact.

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"https://www.tenable.com/security/tns-2016-12");
  script_set_attribute(attribute:"see_also", value:"https://curl.haxx.se/docs/CVE-2016-4802.html");
  script_set_attribute(attribute:"see_also", value:"https://curl.haxx.se/changes.html#7_48_0");
  script_set_attribute(attribute:"see_also", value:"https://www.libssh2.org/adv_20160223.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Tenable SecurityCenter version 5.4.0 or later.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2016-4802");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/02/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/07/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/07/26");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:tenable:securitycenter");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2016-2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("securitycenter_installed.nbin", "securitycenter_detect.nbin");
  script_require_ports("Host/SecurityCenter/Version", "installed_sw/SecurityCenter");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("install_func.inc");

version = get_kb_item("Host/SecurityCenter/Version");
port = 0;
if(empty_or_null(version))
{
  port = 443;
  install = get_single_install(app_name:"SecurityCenter", combined:TRUE, exit_if_unknown_ver:TRUE);
  version = install["version"];
}

fix = "5.4.0";

if (version =~ "^5\.3\.[0-2](\.|$)")
{
  items = make_array("Installed version", version,
                     "Fixed version", fix
                    );

  order = make_list("Installed version", "Fixed version");
  report = report_items_str(report_items:items, ordered_fields:order);

  security_report_v4(severity:SECURITY_WARNING, port:port, extra:report);
}
else
  audit(AUDIT_INST_VER_NOT_VULN, 'SecurityCenter', version);
