#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(59091);
  script_version("1.6");
  script_cvs_date("Date: 2019/12/04");

  script_cve_id(
    "CVE-2012-1516",
    "CVE-2012-1517",
    "CVE-2012-2449",
    "CVE-2012-2450"
  );
  script_bugtraq_id(53369);
  script_xref(name:"VMSA", value:"2012-0009");

  script_name(english:"VMware Player Multiple Vulnerabilities (VMSA-2012-0009)");
  script_summary(english:"Checks VMware Player version");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has a virtualization application affected by multiple
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The VMware Player install detected on the remote host is 3.x earlier
than 3.1.6, or 4.0.x earlier than 4.0.3 and is, therefore,  potentially
affected by the following vulnerabilities :

  - Memory corruption errors exist related to the
    RPC commands handler function which could cause the
    application to crash or possibly allow an attacker to
    execute arbitrary code. Note that these errors only
    affect the 3.x branch. (CVE-2012-1516, CVE-2012-1517)

  - An error in the virtual floppy device configuration
    can allow out-of-bounds memory writes and can allow
    a guest user to crash the VMX process or potentially
    execute arbitrary code on the host. Note that root or
    administrator level privileges in the guest are required
    for successful exploitation along with the existence of
    a virtual floppy device in the guest. (CVE-2012-2449)

  - An error in the virtual SCSI device registration
    process can allow improper memory writes and can allow
    a guest user to crash the VMX process or potentially
    execute arbitrary code on the host. Note that root or
    administrator level privileges are required in the
    guest for successful exploitation along with the
    existence of a virtual SCSI device in the guest.
    (CVE-2012-2450)");
  script_set_attribute(attribute:"see_also", value:"http://www.vmware.com/security/advisories/VMSA-2012-0009.html");
  script_set_attribute(attribute:"see_also", value:"http://lists.vmware.com/pipermail/security-announce/2012/000176.html");
  # https://www.vmware.com/support/player31/doc/releasenotes_player316.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?acb1cf3a");
  # https://www.vmware.com/support/player40/doc/releasenotes_player403.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?258456c3");
  script_set_attribute(attribute:"solution", value:
"Upgrade to VMware Player 3.1.6 / 4.0.3 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/05/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/06/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/05/15");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:vmware:player");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2012-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("vmware_player_detect.nasl");
  script_require_keys("SMB/Registry/Enumerated", "VMware/Player/Version");

  exit(0);
}

include("global_settings.inc");
include("audit.inc");
include("misc_func.inc");
include("smb_func.inc");


version = get_kb_item_or_exit("VMware/Player/Version");

vulnerable = NULL;

if (version =~ '^3\\.')
{
  fix = '3.1.6';
  vulnerable = ver_compare(ver:version, fix:fix, strict:FALSE);
}

if (version =~ '^4\\.0')
{
  fix = '4.0.3';
  vulnerable = ver_compare(ver:version, fix:fix, strict:FALSE);
}

if (vulnerable < 0)
{
  port = kb_smb_transport();

  if (report_verbosity > 0)
  {
    report =
      '\n  Installed version : '+version+
      '\n  Fixed version     : ' + fix + '\n';
    security_hole(port:port, extra:report);
  }
  else security_hole();
}
else audit(AUDIT_INST_VER_NOT_VULN, "VMware Player", version);
