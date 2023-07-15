#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from F5 Networks BIG-IP Solution K91229003.
#
# The text description of this plugin is (C) F5 Networks.
#

include("compat.inc");

if (description)
{
  script_id(118702);
  script_version("1.5");
  script_cvs_date("Date: 2019/05/29 10:47:07");

  script_cve_id("CVE-2017-5715", "CVE-2017-5753", "CVE-2017-5754");

  script_name(english:"F5 Networks BIG-IP : Side-channel processor vulnerabilities (K91229003) (Meltdown) (Spectre)");
  script_summary(english:"Checks the BIG-IP version.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote device is missing a vendor-supplied security patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The following three side-channel attacks were publicly disclosed on
January 3, 2018 :

CVE-2017-5715 Spectre-BTB (previously known as Spectre Variant 2)
Branch target injection

Systems with microprocessors utilizing speculative execution and
indirect branch prediction may allow unauthorized disclosure of
information to an attacker with local user access via a side-channel
analysis.

CVE-2017-5753 Spectre-PHT (previously known as Spectre Variant 1)
Bounds checking bypass Systems with microprocessors utilizing
speculative execution and branch prediction may allow unauthorized
disclosure of information to an attacker with local user access via a
side-channel analysis.

CVE-2017-5754 Meltdown-US (previously known as Meltdown) Rogue data
cache load Systems with microprocessors utilizing speculative
execution and indirect branch prediction may allow unauthorized
disclosure of information to an attacker with local user access via a
side-channel analysis of the data cache.

Impact

F5 continues to investigate the impact of the Spectre and Meltdown
vulnerabilities on our products. F5 is focused onproviding patched
releases as soon as we have fully tested and verified fixes. F5 will
update this article with the most current information as soon as it is
confirmed.

BIG-IP

First and foremost, there is no exposure on BIG-IP products by way
ofthe data plane. All exposure is limited to the control plane (also
known as the management plane).

Furthermore, on the control plane, the vulnerabilities are exploitable
only by four authorized, authenticated account roles: Administrator,
Resource Administrator, Manager, and iRules Manager. You must be
authorized to access the system in one of these roles to even attempt
to exploit the vulnerabilities.

All three vulnerabilities require an attacker who can provideand
runbinary code of their choosing on the BIG-IP platform.

These conditions severely restrict the exposure risk of BIG-IP
products.

For single-tenancy products, such as astandalone BIG-IP appliance, the
risk is limited to a local, authorized user using one of the
vulnerabilities to read information from memory that they would not
normally be able to access, exceeding their privileges. Effectively,
the risk in a single-tenancy situation is that a user may be able to
access kernel-space memory, instead of being limited to their own
user-space.

For multi-tenancy environments, such as cloud, VE, and Virtual
Clustered Multiprocessing (vCMP), the same local risk applies as with
single-tenancy environments local kernel memory access. Additionally,
the risk of attacks across guests exists, or attacks against the
hypervisor/host. In cloud and VE environments, preventing these new
attacks falls on the hypervisor/host platform, outside the scope of
F5's ability to support or patch. Please contact your cloud provider
or hypervisor vendor to ensure their platforms or products are
protected against Spectre and Meltdown.

For vCMP environments, F5 believes that while the Spectre-PHTand
Meltdown-USattacks do offer a theoretical possibility of
guest-to-guest or guest-to-host attacks, these would be very difficult
to successfully conduct in the BIG-IP environment. The primary risk in
the vCMP environment comes from Spectre-BTB, but this risk exists only
when vCMP guests are configured to use a single core. If the vCMP
guests are configured to use two or more cores, the
Spectre-BTBvulnerability is eliminated.

F5 is working with our hardware component vendors to determine the
scope of vulnerabilities across our various generations of hardware
platforms. All of the information we currently have from our vendors
is represented in this Security Advisory. We are working to obtain the
remaining information from our vendors and will update the security
advisory as we receive new information regarding our hardware
platforms.

We are also testing the fixes produced by the Linux community. We are
conducting anextensive test campaign to characterize the impact of the
fixes on system performance and stabilityto ensure, as best we can, a
good experience for our customers. We do not want to rush the process
and release fixes without a full understanding of any potential
issues. Given the limited exposure, as detailed above, the complexity
of the fixes, and the potential issues that we and others have seen,
we believe a detailed approach is warranted and that rushing a fix
could result in an impact to system stability or unacceptable
performance costs. We will update this article with details of our
fixes as they become available.

To determine which vulnerabilities affect each platform and the
processor type each platform uses, refer to the following table.

Note : In the following table, only one entry is shown for platform
models that may have several variants. For example, BIG-IP 11000,
BIG-IP 11050, BIG-IP 11050F, and BIG-IP 11050N are all vulnerable and
included in the table as 'BIG-IP 110x0'. Some platforms may have
multiple vendor processors, such as the iSeries platforms, which have
one or more Intel core processors and may have a vulnerable ARM
processor in one or more subsystems. F5 does not believe that ARM
processors in these subsystems are accessible to attackers, unless
some other code-execution vulnerability is present, but the
information is being provided out of an abundance of caution.

Model Processor type Vulnerable to CVE-2017-5753 Spectre-PHT
Vulnerable to CVE-2017-5715 Spectre-BTB Vulnerable to CVE-2017-5754
Meltdown-US VIPRION B21x0 Intel Y Y Y VIPRION B2250 Intel Y Y Y
VIPRION B4100 AMD Y Y** N VIPRION B4200 AMD Y Y** N VIPRION B43x0
Intel Y Y Y VIPRION B44x0 Intel Y Y Y BIG-IP 800 Intel Y** N Y**
BIG-IP 1600 Intel Y** N Y** BIG-IP 3600 Intel Y** N Y** BIG-IP 3900
Intel Y** N Y** BIG-IP2xx0 Intel Y Y Y BIG-IP4xx0 Intel Y Y Y
BIG-IP5xx0 Intel Y Y Y BIG-IP7xx0 Intel Y Y Y BIG-IP10xx0 Intel Y Y Y
BIG-IP12xx0 Intel Y Y Y BIG-IPi2x00 Intel, ARM Y Y Y BIG-IPi4x00
Intel, ARM Y Y Y BIG-IPi5x00 Intel, ARM Y Y Y BIG-IPi7x00 Intel, ARM Y
Y Y BIG-IPi10x00 Intel, ARM Y Y Y BIG-IP6400 AMD Y Y** N BIG-IP6900
AMD Y Y** N BIG-IP89x0 AMD Y Y** N BIG-IP110x0 AMD Y Y** N

**Intel and AMD have not responded to requests for information
relating to the specific processors used in these platforms.
Therefore, based on their public statements and in the interests of
security, F5 will proceed as if these platforms are vulnerable.

Note : Platform models that have reached End of Technical Support
(EoTS) will not be evaluated. For more information, refer toK4309: F5
platform lifecycle support policy.

BIG-IQ and Enterprise Manager

Systems with microprocessors that use speculative execution and
indirect branch prediction may allow unauthorized disclosure of
information to an attacker with local user access by way ofa
side-channel analysis.

To determine which vulnerabilities affect each platform and the
processor type each platform uses, refer to the following table.

Model Processor type Vulnerable to CVE-2017-5753 Spectre-PHT
Vulnerable to CVE-2017-5715 Spectre-BTB Vulnerable to CVE-2017-5754
Meltdown-US BIG-IQ 7000 Intel Y Y Y Enterprise Manager 4000 Intel Y**
N Y**

**Intel hasnot responded to requests for information relating to the
specific processors used in these platforms. Therefore, based on their
public statements and in the interests of security, F5 will proceed as
if these platforms are vulnerable.

Note : Platform models that have reached End of Technical Support
(EoTS) will not be evaluated. For more information, refer toK4309: F5
platform lifecycle support policy.

Traffix

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
    value:"https://support.f5.com/csp/article/K4309"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://support.f5.com/csp/article/K91229003"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade to one of the non-vulnerable versions listed in the F5
Solution K91229003."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:H/PR:L/UI:N/S:C/C:H/I:N/A:N");
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
  script_set_attribute(attribute:"cpe", value:"cpe:/a:f5:big-ip_webaccelerator");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:f5:big-ip");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/01/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/01/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/11/02");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2018-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");
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

sol = "K91229003";
vmatrix = make_array();

if (report_paranoia < 2) audit(AUDIT_PARANOID);

# AFM
vmatrix["AFM"] = make_array();
vmatrix["AFM"]["affected"  ] = make_list("13.0.0-13.1.0","12.1.0-12.1.3","11.6.1-11.6.3","11.5.1-11.5.5","11.2.1");
vmatrix["AFM"]["unaffected"] = make_list("15.0.0","14.0.0","13.1.0.4","13.0.1","12.1.3.3","11.6.3.1","11.5.6");

# AM
vmatrix["AM"] = make_array();
vmatrix["AM"]["affected"  ] = make_list("13.0.0-13.1.0","12.1.0-12.1.3","11.6.1-11.6.3","11.5.1-11.5.5","11.2.1");
vmatrix["AM"]["unaffected"] = make_list("15.0.0","14.0.0","13.1.0.4","13.0.1","12.1.3.3","11.6.3.1","11.5.6");

# APM
vmatrix["APM"] = make_array();
vmatrix["APM"]["affected"  ] = make_list("13.0.0-13.1.0","12.1.0-12.1.3","11.6.1-11.6.3","11.5.1-11.5.5","11.2.1");
vmatrix["APM"]["unaffected"] = make_list("15.0.0","14.0.0","13.1.0.4","13.0.1","12.1.3.3","11.6.3.1","11.5.6");

# ASM
vmatrix["ASM"] = make_array();
vmatrix["ASM"]["affected"  ] = make_list("13.0.0-13.1.0","12.1.0-12.1.3","11.6.1-11.6.3","11.5.1-11.5.5","11.2.1");
vmatrix["ASM"]["unaffected"] = make_list("15.0.0","14.0.0","13.1.0.4","13.0.1","12.1.3.3","11.6.3.1","11.5.6");

# AVR
vmatrix["AVR"] = make_array();
vmatrix["AVR"]["affected"  ] = make_list("13.0.0-13.1.0","12.1.0-12.1.3","11.6.1-11.6.3","11.5.1-11.5.5","11.2.1");
vmatrix["AVR"]["unaffected"] = make_list("15.0.0","14.0.0","13.1.0.4","13.0.1","12.1.3.3","11.6.3.1","11.5.6");

# GTM
vmatrix["GTM"] = make_array();
vmatrix["GTM"]["affected"  ] = make_list("13.0.0-13.1.0","12.1.0-12.1.3","11.6.1-11.6.3","11.5.1-11.5.5","11.2.1");
vmatrix["GTM"]["unaffected"] = make_list("15.0.0","14.0.0","13.1.0.4","13.0.1","12.1.3.3","11.6.3.1","11.5.6");

# LC
vmatrix["LC"] = make_array();
vmatrix["LC"]["affected"  ] = make_list("13.0.0-13.1.0","12.1.0-12.1.3","11.6.1-11.6.3","11.5.1-11.5.5","11.2.1");
vmatrix["LC"]["unaffected"] = make_list("15.0.0","14.0.0","13.1.0.4","13.0.1","12.1.3.3","11.6.3.1","11.5.6");

# LTM
vmatrix["LTM"] = make_array();
vmatrix["LTM"]["affected"  ] = make_list("13.0.0-13.1.0","12.1.0-12.1.3","11.6.1-11.6.3","11.5.1-11.5.5","11.2.1");
vmatrix["LTM"]["unaffected"] = make_list("15.0.0","14.0.0","13.1.0.4","13.0.1","12.1.3.3","11.6.3.1","11.5.6");

# PEM
vmatrix["PEM"] = make_array();
vmatrix["PEM"]["affected"  ] = make_list("13.0.0-13.1.0","12.1.0-12.1.3","11.6.1-11.6.3","11.5.1-11.5.5","11.2.1");
vmatrix["PEM"]["unaffected"] = make_list("15.0.0","14.0.0","13.1.0.4","13.0.1","12.1.3.3","11.6.3.1","11.5.6");

# WAM
vmatrix["WAM"] = make_array();
vmatrix["WAM"]["affected"  ] = make_list("13.0.0-13.1.0","12.1.0-12.1.3","11.6.1-11.6.3","11.5.1-11.5.5","11.2.1");
vmatrix["WAM"]["unaffected"] = make_list("15.0.0","14.0.0","13.1.0.4","13.0.1","12.1.3.3","11.6.3.1","11.5.6");


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
