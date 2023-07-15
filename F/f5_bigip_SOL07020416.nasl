#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from F5 Networks BIG-IP Solution K07020416.
#
# The text description of this plugin is (C) F5 Networks.
#

include('deprecated_nasl_level.inc');
include("compat.inc");

if (description)
{
  script_id(151461);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/10/28");

  script_cve_id("CVE-2017-18344");

  script_name(english:"F5 Networks BIG-IP : Linux kernel vulnerability (K07020416)");
  script_summary(english:"Checks the BIG-IP version.");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote device is missing a vendor-supplied security patch."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The timer_create syscall implementation in kernel/time/posix-timers.c
in the Linux kernel before 4.14.8 doesn't properly validate the
sigevent->sigev_notify field, which leads to out-of-bounds access in
the show_timer function (called when /proc/$PID/timers is read). This
allows userspace applications to read arbitrary kernel memory (on a
kernel built with CONFIG_POSIX_TIMERS and CONFIG_CHECKPOINT_RESTORE).
(CVE-2017-18344)

Impact

A local attacker may use this vulnerability to expose sensitive
information or cause a denial of service (DoS), makingthe system
unresponsive."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://support.f5.com/csp/article/K07020416"
  );
  script_set_attribute(
    attribute:"solution",
    value:
"Upgrade to one of the non-vulnerable versions listed in the F5
Solution K07020416."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:f5:big-ip_access_policy_manager");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:f5:big-ip_advanced_firewall_manager");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:f5:big-ip_application_acceleration_manager");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:f5:big-ip_application_security_manager");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:f5:big-ip_application_visibility_and_reporting");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:f5:big-ip_global_traffic_manager");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:f5:big-ip_link_controller");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:f5:big-ip_local_traffic_manager");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:f5:big-ip_policy_enforcement_manager");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:f5:big-ip");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/07/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/12/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/07/08");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2021-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");
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

sol = "K07020416";
vmatrix = make_array();

if (report_paranoia < 2) audit(AUDIT_PARANOID);

# AFM
vmatrix["AFM"] = make_array();
vmatrix["AFM"]["affected"  ] = make_list("16.0.0-16.0.1","15.1.0-15.1.7","14.1.0-14.1.5","13.1.0-13.1.5");
vmatrix["AFM"]["unaffected"] = make_list("16.1.0","15.1.8");

# AM
vmatrix["AM"] = make_array();
vmatrix["AM"]["affected"  ] = make_list("16.0.0-16.0.1","15.1.0-15.1.7","14.1.0-14.1.5","13.1.0-13.1.5");
vmatrix["AM"]["unaffected"] = make_list("16.1.0","15.1.8");

# APM
vmatrix["APM"] = make_array();
vmatrix["APM"]["affected"  ] = make_list("16.0.0-16.0.1","15.1.0-15.1.7","14.1.0-14.1.5","13.1.0-13.1.5");
vmatrix["APM"]["unaffected"] = make_list("16.1.0","15.1.8");

# ASM
vmatrix["ASM"] = make_array();
vmatrix["ASM"]["affected"  ] = make_list("16.0.0-16.0.1","15.1.0-15.1.7","14.1.0-14.1.5","13.1.0-13.1.5");
vmatrix["ASM"]["unaffected"] = make_list("16.1.0","15.1.8");

# AVR
vmatrix["AVR"] = make_array();
vmatrix["AVR"]["affected"  ] = make_list("16.0.0-16.0.1","15.1.0-15.1.7","14.1.0-14.1.5","13.1.0-13.1.5");
vmatrix["AVR"]["unaffected"] = make_list("16.1.0","15.1.8");

# GTM
vmatrix["GTM"] = make_array();
vmatrix["GTM"]["affected"  ] = make_list("16.0.0-16.0.1","15.1.0-15.1.7","14.1.0-14.1.5","13.1.0-13.1.5");
vmatrix["GTM"]["unaffected"] = make_list("16.1.0","15.1.8");

# LC
vmatrix["LC"] = make_array();
vmatrix["LC"]["affected"  ] = make_list("16.0.0-16.0.1","15.1.0-15.1.7","14.1.0-14.1.5","13.1.0-13.1.5");
vmatrix["LC"]["unaffected"] = make_list("16.1.0","15.1.8");

# LTM
vmatrix["LTM"] = make_array();
vmatrix["LTM"]["affected"  ] = make_list("16.0.0-16.0.1","15.1.0-15.1.7","14.1.0-14.1.5","13.1.0-13.1.5");
vmatrix["LTM"]["unaffected"] = make_list("16.1.0","15.1.8");

# PEM
vmatrix["PEM"] = make_array();
vmatrix["PEM"]["affected"  ] = make_list("16.0.0-16.0.1","15.1.0-15.1.7","14.1.0-14.1.5","13.1.0-13.1.5");
vmatrix["PEM"]["unaffected"] = make_list("16.1.0","15.1.8");


if (bigip_is_affected(vmatrix:vmatrix, sol:sol))
{
  if (report_verbosity > 0) security_note(port:0, extra:bigip_report_get());
  else security_note(0);
  exit(0);
}
else
{
  tested = bigip_get_tested_modules();
  audit_extra = "For BIG-IP module(s) " + tested + ",";
  if (tested) audit(AUDIT_INST_VER_NOT_VULN, audit_extra, version);
  else audit(AUDIT_HOST_NOT, "running any of the affected modules");
}
