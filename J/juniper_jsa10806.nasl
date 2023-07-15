#TRUSTED 1f1ad4decafb4308e95c20f051ad933527eb6e22e6edb98a2bc93dcb233d5aa7c171eaa49bf0baf919115d2d3cec2802368171272d03865fec22d3577e4e42c42dee349be27aed5a9ee04016e915a650a661f38a67c394986ee09beba5f3bb7089263aa8347294d582ca833f416d5b77d33775d1c8a32994a4ef889e74684f89f2cb73401faca9352f411330edd77ebda6fb582874020baa72c014e0245dfd774236f70be1fb00131148c2d3d491debe527dde93f63a01c5ce05dfd0034dd7ace13742acdd541db9923c776ebec5328e1a5af8d5e26c59cabc7ea076191da53c50f5faa8f4c7016ca026cc51d0a517998656a6a5809d4aa07c71891905cc7779d37bbee89502ce78e19453a8d7200916ea01d8a27380f2e8c54cd7e1d86dcab0df05fb5fd2d70d70bc40bb9bbdc2c47165609eb5f0968cb16e8a2afcda77d7ef93616567d85cf7a57af6da148bb55b9737260631eeae0e901243a3386d2c0d372914339f5a4f09c166c4484dc32c6bee6c8ce8c98ed5b6c89bcef72038f85b196422f1e36ea60d69e00d26327d2130c53de5d9ea59ff23f3f6b3e1d5be9c64ea50e9587803169f9fe3d694597f6668cd599d3177d70bf92da16a2fc4e6600c775ada690360e41d132f95747ba0c574df626d5c74d2b92b903b79d9b2372486ab76f6122a4f325965b1d4e884aa67abe663bc2ea8d32199e41d44bc10064c0d23
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(102081);
  script_version ("1.5");
  script_cvs_date("Date: 2019/01/17 14:06:00");

  script_cve_id("CVE-2017-10604");
  script_xref(name:"JSA", value:"JSA10806");

  script_name(english:"Juniper Junos SRX Cluster Synchronization Failover Errors (JSA10806)");
  script_summary(english:"Checks the Junos version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is affected by a vulnerability that impacts device
integrity.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number and configuration, the
remote Juniper Junos device is affected by a flaw in the handling of
cluster synchronization and failover operations whenever the root
account has been locked out. An unauthenticated, remote attacker can
exploit this, via a series of unsuccessful login attempts, to cause
synchronization or failover errors on the device.");
  script_set_attribute(attribute:"see_also", value:"https://kb.juniper.net/InfoCenter/index?page=content&id=JSA10806");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant Junos software release referenced in Juniper
security advisory JSA10806.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-10604");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/07/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/07/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/07/31");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:juniper:junos");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Junos Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2017-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("junos_version.nasl");
  script_require_keys("Host/Juniper/JUNOS/Version", "Host/Juniper/model");

  exit(0);
}

include("audit.inc");
include("junos_kb_cmd_func.inc");

ver   = get_kb_item_or_exit('Host/Juniper/JUNOS/Version');
model = get_kb_item_or_exit('Host/Juniper/model');

if (model !~ "^SRX")
  audit(AUDIT_HOST_NOT, 'a SRX device');

fixes = make_array();

fixes['12.1X46'] = '12.1X46-D65';
fixes['12.3X48'] = '12.3X48-D45';
fixes['15.1X49'] = '15.1X49-D75';

fix = check_junos(ver:ver, fixes:fixes, exit_on_fail:TRUE);

# Check for J-Web
override = TRUE;
buf = junos_command_kb_item(cmd:"show configuration | display set");
if (buf)
{
  pat_lockout = "^set system login retry-options lockout-period";
  pat_clust = "^set chassis cluster";
  if (!junos_check_config(buf:buf, pattern:pat_lockout) ||
      !junos_check_config(buf:buf, pattern:pat_clust))
    audit(AUDIT_HOST_NOT, 'affected because root lockout or cluster mode is not enabled.');

  override = FALSE;
}

junos_report(ver:ver, fix:fix, model:model, override:override, severity:SECURITY_WARNING);
