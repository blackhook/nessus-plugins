#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(102780);
  script_version("1.6");
  script_cvs_date("Date: 2019/11/12");

  script_cve_id("CVE-2017-12859");
  script_bugtraq_id(100417);

  script_name(english:"NetApp ONTAP 8.x.x < 8.2.5 (NTAP-20170815-0002)");
  script_summary(english:"Checks the version of ONTAP.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by a denial-of-service vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of NetApp ONTAP running on the remote host is 8.x.x
prior to 8.2.5. It is, therefore, affected by a denial-of-service
vulnerability. A remote unauthenticated attacker could leverage
this vulnerability and cause a denial-of-service condition against
affected systems running 7-Mode in NFS environments.

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  # https://kb.netapp.com/support/s/article/ka51A0000008SvrQAE/NTAP-20170815-0002
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ef0ce716");
  script_set_attribute(attribute:"solution", value:
"Upgrade to NetApp ONTAP version 8.2.5 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-12859");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/08/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/08/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/08/25");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:netapp:data_ontap");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2017-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("netapp_ontap_detect.nbin");
  script_require_keys("Host/NetApp/ONTAP/display_version", "Host/NetApp/ONTAP/version", "Host/NetApp/ONTAP/mode");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

app_name = "NetApp ONTAP";
display_version = get_kb_item_or_exit("Host/NetApp/ONTAP/display_version");
version = get_kb_item_or_exit("Host/NetApp/ONTAP/version");
mode = get_kb_item_or_exit("Host/NetApp/ONTAP/mode");

# prior to version 8 7-mode did not exist. The system is not vulnerable
#   if 7-mode is disabled. versions prior to 8 will report as not in 7-mode.
if (!mode)
  audit(AUDIT_OS_CONF_NOT_VULN, app_name);

# fix is 8.2.5 and later
if (ver_compare(ver:version, minver:"8.0.0", fix:"8.2.5", strict:FALSE) < 0)
{
  display_fix = "8.2.5";

  port = 0;
  report =
    '\n  Installed version : ' + display_version +
    '\n  Fixed version     : ' + display_fix +
    '\n';

  security_report_v4(port:port, extra:report, severity:SECURITY_WARNING);
}
else audit(AUDIT_INST_VER_NOT_VULN, app_name, display_version);
