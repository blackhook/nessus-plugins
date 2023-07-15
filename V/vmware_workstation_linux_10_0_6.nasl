#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(84222);
  script_version("1.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/09/21");

  script_cve_id("CVE-2015-2341");
  script_bugtraq_id(75094);
  script_xref(name:"VMSA", value:"2015-0004");

  script_name(english:"VMware Workstation 10.x < 10.0.6 RPC Command DoS (VMSA-2015-0004) (Linux)");
  script_summary(english:"Checks the VMware Workstation version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has a virtualization application installed that is
affected by a denial of service vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of VMware Workstation installed on the remote Linux host
is 10.x prior to 10.0.6. It is, therefore, affected by a denial of
service vulnerability due to improper validation of user-supplied
input to a remote procedure call (RPC) command. An unauthenticated,
remote attacker can exploit this, via a crafted command, to crash the
host or guest operating systems.");
  script_set_attribute(attribute:"see_also", value:"http://www.vmware.com/security/advisories/VMSA-2015-0004.html");
  script_set_attribute(attribute:"solution", value:"Upgrade to VMware Workstation version 10.0.6 or later.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2015-2341");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/06/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/06/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/06/16");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:vmware:workstation");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015-2020 Tenable Network Security, Inc.");
  script_family(english:"General");

  script_dependencies("vmware_workstation_linux_installed.nbin");
  script_require_keys("Host/uname", "Host/VMware Workstation/Version");
  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

if ("linux" >!< tolower(get_kb_item("Host/uname")))
  audit(AUDIT_OS_NOT, "Linux");

version = get_kb_item_or_exit("Host/VMware Workstation/Version");

fixed  = "10.0.6";
if (version =~ "^10\." && ver_compare(ver:version, fix:fixed, strict:FALSE) == -1)
{
  report +=
    '\n  Installed version : ' + version +
    '\n  Fixed version     : ' + fixed +
    '\n';
  security_report_v4(port:0, extra:report, severity:SECURITY_HOLE);
}
else audit(AUDIT_INST_VER_NOT_VULN, "VMware Workstation", version);
