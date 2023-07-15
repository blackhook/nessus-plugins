#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from F5 Networks BIG-IP Solution K21344224.
#
# The text description of this plugin is (C) F5 Networks.
#

include("compat.inc");

if (description)
{
  script_id(118641);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/01/31");

  script_cve_id("CVE-2018-3665");

  script_name(english:"F5 Networks BIG-IP : Lazy FP state restore vulnerability (K21344224)");
  script_summary(english:"Checks the BIG-IP version.");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote device is missing a vendor-supplied security patch."
  );
  script_set_attribute(
    attribute:"description",
    value:
"System software utilizing Lazy FP state restore technique on systems
using Intel Core-based microprocessors may potentially allow a local
process to infer data from another process through a speculative
execution side channel. (CVE-2018-3665)

A Floating-Point (FP) state information leakage flaw was found in the
way the Linux kernel saves and restores the FP state during task
switch. Linux kernels that follow the 'Lazy FP Restore' scheme are
vulnerable to the FP state information leakage issue. An unprivileged,
local attacker can use this flaw to read FP state bits by conducting
targeted cache side-channel attacks, similar to the Meltdown
vulnerability disclosed earlier this year.

Impact

This vulnerability requires an attacker to induce speculative
execution of code to acquire privileged information, then leak that
information via a micro-architectural side-channel. Intel Core
processors are affected. AMD processors are not affected.

F5 is investigating the impact of this vulnerability on our products.
F5 is focused on providing patched releases as soon as we have fully
tested and verified fixes. F5 will update this article with the most
current information as soon as it is confirmed.

BIG-IP

This vulnerability requires an attacker who can provide and run binary
code of their choosing on the BIG-IP platform. This raises a high bar
for attackers attempting to target BIG-IP systems over a network and
would require an additional, un-patched, user-space remote code
execution vulnerability to exploit these new issues.

The only administrative roles on a BIG-IP system that can execute
binary code or exploitable analogs, such as JavaScript, are the
Administrator, Resource Administrator, Manager, and iRules Manager
roles. The Administrator and Resource Administrator roles already have
nearly complete access to the system and all secrets on the system
that are not protected by hardware-based encryption. The Manager and
iRules Manager roles have access restrictions, but they can install
new iRulesLX code. A malicious authorized Manager or iRules Manager
can install malicious binary code to exploit these information leaks
and gain more privileged access. F5 recommends limiting these roles to
trusted employees.

To determine the processor type used by each platform and if the
platform is affected by thisvulnerability, refer to the following
table.

Note : In the following table, only one entry is shown for platform
models that may have several variants. For example, BIG-IP 11000,
BIG-IP 11050, BIG-IP 11050F, and BIG-IP 11050N are allincluded in the
table as 'BIG-IP 110x0'. Some platforms may have multiple vendor
processors, such as the iSeries platforms, which have one or more
Intel Core processors and may have a vulnerable ARM processor in one
or more subsystems. F5 does not believe that ARM processors in these
subsystems are accessible to attackers, unless some other
code-execution vulnerability is present, but the information is being
provided out of an abundance of caution.

Model Processor type Vulnerable to CVE-2018-3665 Lazy FP state restore
VIPRION B21x0 Intel N* VIPRION B2250 Intel N* VIPRION B4100 AMD N
VIPRION B4200 AMD N VIPRION B43x0 Intel N* VIPRION B44x0 Intel N*
BIG-IP2xx0 Intel Y BIG-IP4xx0 Intel N* BIG-IP5xx0 Intel N* BIG-IP7xx0
Intel N* BIG-IP10xx0 Intel N* BIG-IP 110x0 AMD N BIG-IP12xx0 Intel N*
BIG-IPi2x00 Intel, ARM N* BIG-IPi4x00 Intel, ARM N* BIG-IPi5x00 Intel,
ARM N* BIG-IPi7x00 Intel, ARM N* BIG-IPi10x00 Intel, ARM N* BIG-IP 800
Intel Y BIG-IP 1600 Intel Y BIG-IP 3600 Intel Y BIG-IP 3900 Intel N*
BIG-IP6400 AMD N BIG-IP6900 AMD N BIG-IP89x0 AMD N

*Intel Xeon based processors are not vulnerable to this issue.

Note : Platform models that have reached End of Technical Support
(EoTS) will not be evaluated. For more information, refer toK4309: F5
platform lifecycle support policy.

BIG-IQ and Enterprise Manager

To determine the processor type used by each platform and if the
platform is affected by thisvulnerability, refer to the following
table.

Model Processor type Vulnerable to CVE-2018-3665 Lazy FP state restore
BIG-IQ 7000 Intel Y Enterprise Manager 4000 Intel Y

Note : Platform models that have reached EoTS will not be evaluated.
For more information, refer toK4309: F5 platform lifecycle support
policy.

ARX

To determine the processor type used by each platform and if the
platform is affected by thisvulnerability, refer to the following
table.

Model Processor type Vulnerable to CVE-2018-3665 Lazy FP state restore
ARX 1500+ Intel Y* ARX 2500 Intel Y* ARX 4000/4000+ Intel Y*

*The specified platforms contain the affected processor. However, F5
identifies the ARX software vulnerability status as Not vulnerable
because the attacker cannot exploit the code in default, standard, or
recommended configurations.

Note : Platform models that have reached EoTS will not be evaluated.
For more information, refer toK4309: F5 platform lifecycle support
policy.

Traffix SDC

Systems with microprocessors that use speculative execution and
indirect branch prediction may allow unauthorized disclosure of
information to an attacker with local user access by way of a
side-channel analysis.

LineRate

Systems with microprocessors that use speculative execution and
indirect branch prediction may allow unauthorized disclosure of
information to an attacker with local user access by way of a
side-channel analysis.

For products with None in the Versions known to be vulnerable column
in the following table, there is no impact."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://support.f5.com/csp/article/K21344224"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://support.f5.com/csp/article/K4309"
  );
  script_set_attribute(
    attribute:"solution",
    value:
"Upgrade to one of the non-vulnerable versions listed in the F5
Solution K21344224."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:H/PR:L/UI:N/S:C/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-3665");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

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
  script_set_attribute(attribute:"cpe", value:"cpe:/a:f5:big-ip_webaccelerator");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:f5:big-ip");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/06/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/06/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/11/02");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2018-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");
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

sol = "K21344224";
vmatrix = make_array();

if (report_paranoia < 2) audit(AUDIT_PARANOID);

# AFM
vmatrix["AFM"] = make_array();
vmatrix["AFM"]["affected"  ] = make_list("14.0.0","13.0.0-13.1.1","12.1.0-12.1.5","11.2.1-11.6.5");
vmatrix["AFM"]["unaffected"] = make_list("14.1.0","14.0.0.3","13.1.1.2");

# AM
vmatrix["AM"] = make_array();
vmatrix["AM"]["affected"  ] = make_list("14.0.0","13.0.0-13.1.1","12.1.0-12.1.5","11.2.1-11.6.5");
vmatrix["AM"]["unaffected"] = make_list("14.1.0","14.0.0.3","13.1.1.2");

# APM
vmatrix["APM"] = make_array();
vmatrix["APM"]["affected"  ] = make_list("14.0.0","13.0.0-13.1.1","12.1.0-12.1.5","11.2.1-11.6.5");
vmatrix["APM"]["unaffected"] = make_list("14.1.0","14.0.0.3","13.1.1.2");

# ASM
vmatrix["ASM"] = make_array();
vmatrix["ASM"]["affected"  ] = make_list("14.0.0","13.0.0-13.1.1","12.1.0-12.1.5","11.2.1-11.6.5");
vmatrix["ASM"]["unaffected"] = make_list("14.1.0","14.0.0.3","13.1.1.2");

# AVR
vmatrix["AVR"] = make_array();
vmatrix["AVR"]["affected"  ] = make_list("14.0.0","13.0.0-13.1.1","12.1.0-12.1.5","11.2.1-11.6.5");
vmatrix["AVR"]["unaffected"] = make_list("14.1.0","14.0.0.3","13.1.1.2");

# GTM
vmatrix["GTM"] = make_array();
vmatrix["GTM"]["affected"  ] = make_list("14.0.0","13.0.0-13.1.1","12.1.0-12.1.5","11.2.1-11.6.5");
vmatrix["GTM"]["unaffected"] = make_list("14.1.0","14.0.0.3","13.1.1.2");

# LC
vmatrix["LC"] = make_array();
vmatrix["LC"]["affected"  ] = make_list("14.0.0","13.0.0-13.1.1","12.1.0-12.1.5","11.2.1-11.6.5");
vmatrix["LC"]["unaffected"] = make_list("14.1.0","14.0.0.3","13.1.1.2");

# LTM
vmatrix["LTM"] = make_array();
vmatrix["LTM"]["affected"  ] = make_list("14.0.0","13.0.0-13.1.1","12.1.0-12.1.5","11.2.1-11.6.5");
vmatrix["LTM"]["unaffected"] = make_list("14.1.0","14.0.0.3","13.1.1.2");

# PEM
vmatrix["PEM"] = make_array();
vmatrix["PEM"]["affected"  ] = make_list("14.0.0","13.0.0-13.1.1","12.1.0-12.1.5","11.2.1-11.6.5");
vmatrix["PEM"]["unaffected"] = make_list("14.1.0","14.0.0.3","13.1.1.2");

# WAM
vmatrix["WAM"] = make_array();
vmatrix["WAM"]["affected"  ] = make_list("14.0.0","13.0.0-13.1.1","12.1.0-12.1.5","11.2.1-11.6.5");
vmatrix["WAM"]["unaffected"] = make_list("14.1.0","14.0.0.3","13.1.1.2");


if (bigip_is_affected(vmatrix:vmatrix, sol:sol))
{
  if (report_verbosity > 0) security_warning(port:0, extra:bigip_report_get());
  else security_warning(0);
  exit(0);
}
else
{
  tested = bigip_get_tested_modules();
  audit_extra = "For BIG-IP module(s) " + tested + ",";
  if (tested) audit(AUDIT_INST_VER_NOT_VULN, audit_extra, version);
  else audit(AUDIT_HOST_NOT, "running any of the affected modules");
}
