#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from F5 Networks BIG-IP Solution K13600.
#
# The text description of this plugin is (C) F5 Networks.
#

include("compat.inc");

if (description)
{
  script_id(78136);
  script_version("1.15");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/03/10");

  script_bugtraq_id(53897);

  script_name(english:"F5 Networks BIG-IP : SSH vulnerability (K13600)");
  script_summary(english:"Checks the BIG-IP version.");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote device is missing a vendor-supplied security patch."
  );
  script_set_attribute(
    attribute:"description",
    value:
"A platform-specific remote access vulnerability has been discovered
that may allow a remote user to gain privileged access to affected
systems using secure shell (SSH). The vulnerability is caused by a
configuration error, and is not the result of an underlying SSH
defect.

The following platforms are affected by this issue :

VIPRION B2100, B4100, and B4200

BIG-IP 520, 540, 1000, 2000, 2400, 5000, 5100, 1600, 3600, 3900, 6900,
8900, 8950, 11000, and 11050

BIG-IP Virtual Edition

Enterprise Manager 3000 and 4000

Note : Systems that are licensed to run in Appliance mode on BIG-IP
10.2.1 HF3 or later are not susceptible to this vulnerability. For
more information about Appliance mode, refer to K12815: Overview of
Appliance mode.

The only sign that this vulnerability may have been exploited on an
affected system would be the appearance of unexpected root login
messages in the /var/log/secure file. However, there is no way to tell
from any specific login message whether it was the result of this
vulnerability. Further, it is possible for a privileged account to
eliminate traces of illicit activity by modifying the log files.

Neither a strong password policy nor remote authentication helps
mitigate the issue. For information about protecting your system from
exploitation, refer to the Recommended Action section below.

F5 would like to acknowledge Florent Daigniere of Matta Consulting for
bringing this issue to our attention, and for following the highest
standards of responsible disclosure.

Impact

Privileged (root) access may be granted to unauthenticated users."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://support.f5.com/csp/article/K12815"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://support.f5.com/csp/article/K13600"
  );
  script_set_attribute(
    attribute:"solution",
    value:
"Upgrade to one of the non-vulnerable versions listed in the F5
Solution K13600."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:f5:big-ip_access_policy_manager");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:f5:big-ip_application_security_manager");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:f5:big-ip_application_visibility_and_reporting");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:f5:big-ip_global_traffic_manager");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:f5:big-ip_link_controller");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:f5:big-ip_local_traffic_manager");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:f5:big-ip_wan_optimization_manager");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:f5:big-ip");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:f5:big-ip_protocol_security_manager");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/06/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/06/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/10/10");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"F5 Networks Local Security Checks");

  script_dependencies("f5_bigip_detect.nbin");
  script_require_keys("Host/local_checks_enabled", "Host/BIG-IP/hotfix", "Host/BIG-IP/modules", "Host/BIG-IP/version", "Settings/ParanoidReport");

  exit(0);
}


include("f5_func.inc");

if ( ! get_kb_item("Host/local_checks_enabled") ) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
version = get_kb_item("Host/BIG-IP/version");
if ( ! version ) audit(AUDIT_OS_NOT, "F5 Networks BIG-IP");
if ( isnull(get_kb_item("Host/BIG-IP/hotfix")) ) audit(AUDIT_KB_MISSING, "Host/BIG-IP/hotfix");
if ( ! get_kb_item("Host/BIG-IP/modules") ) audit(AUDIT_KB_MISSING, "Host/BIG-IP/modules");

sol = "K13600";
vmatrix = make_array();

if (report_paranoia < 2) audit(AUDIT_PARANOID);

# APM
vmatrix["APM"] = make_array();
vmatrix["APM"]["affected"  ] = make_list("10.1.0-10.2.3HF1","11.0.0-11.0.0HF1","11.1.0-11.1.0HF2");
vmatrix["APM"]["unaffected"] = make_list("10.2.4","11.0.0HF2","11.1.0HF3","11.2","11.3","11.4");

# ASM
vmatrix["ASM"] = make_array();
vmatrix["ASM"]["affected"  ] = make_list("9.2.0-9.4.8HF4","10.0.0-10.2.3HF1","11.0.0-11.0.0HF1","11.1.0-11.1.0HF2");
vmatrix["ASM"]["unaffected"] = make_list("9.4.8HF5","10.2.4","11.0.0HF2","11.1.0HF3","11.2","11.3","11.4");

# AVR
vmatrix["AVR"] = make_array();
vmatrix["AVR"]["affected"  ] = make_list("11.0.0-11.0.0HF1","11.1.0-11.1.0HF2");
vmatrix["AVR"]["unaffected"] = make_list("11.0.0HF2","11.1.0HF3","11.2","11.3","11.4");

# GTM
vmatrix["GTM"] = make_array();
vmatrix["GTM"]["affected"  ] = make_list("9.2.2-9.4.8HF4","10.0.0-10.2.3HF1","11.0.0-11.0.0HF1","11.1.0-11.1.0HF2");
vmatrix["GTM"]["unaffected"] = make_list("9.4.8HF5","10.2.4","11.0.0HF2","11.1.0HF3","11.2","11.3","11.4");

# LC
vmatrix["LC"] = make_array();
vmatrix["LC"]["affected"  ] = make_list("9.2.2-9.4.8HF4","10.0.0-10.2.3HF1","11.0.0-11.0.0HF1","11.1.0-11.1.0HF2");
vmatrix["LC"]["unaffected"] = make_list("9.4.8HF5","10.2.4","11.0.0HF2","11.1.0HF3","11.2","11.3");

# LTM
vmatrix["LTM"] = make_array();
vmatrix["LTM"]["affected"  ] = make_list("9.0.0-9.4.8HF4","10.0.0-10.2.3HF1","11.0.0-11.0.0HF1","11.1.0-11.1.0HF2");
vmatrix["LTM"]["unaffected"] = make_list("9.4.8HF5","10.2.4","11.0.0HF2","11.1.0HF3","11.2","11.3","11.4");

# PSM
vmatrix["PSM"] = make_array();
vmatrix["PSM"]["affected"  ] = make_list("9.4.5-9.4.8HF4","10.0.0-10.2.3HF1","11.0.0-11.0.0HF1","11.1.0-11.1.0HF2");
vmatrix["PSM"]["unaffected"] = make_list("9.4.8HF5","10.2.4","11.0.0HF2","11.1.0HF3","11.2","11.3","11.4");

# WOM
vmatrix["WOM"] = make_array();
vmatrix["WOM"]["affected"  ] = make_list("10.0.0-10.2.3HF1","11.0.0-11.0.0HF1","11.1.0-11.1.0HF2");
vmatrix["WOM"]["unaffected"] = make_list("10.2.4","11.0.0HF2","11.1.0HF3","11.2","11.3");


if (bigip_is_affected(vmatrix:vmatrix, sol:sol))
{
  if (report_verbosity > 0) security_hole(port:0, extra:bigip_report_get());
  else security_hole(0);
  exit(0);
}
else
{
  tested = bigip_get_tested_modules();
  audit_extra = "For BIG-IP module(s) " + tested + ",";
  if (tested) audit(AUDIT_INST_VER_NOT_VULN, audit_extra, version);
  else audit(AUDIT_HOST_NOT, "running any of the affected modules");
}
