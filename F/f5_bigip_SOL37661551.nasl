#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from F5 Networks BIG-IP Solution K37661551.
#
# The text description of this plugin is (C) F5 Networks.
#

include("compat.inc");

if (description)
{
  script_id(138233);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/04/07");

  script_cve_id("CVE-2020-12662", "CVE-2020-12663");

  script_name(english:"F5 Networks BIG-IP : Unbound DNS Cache vulnerabilities (K37661551)");
  script_summary(english:"Checks the BIG-IP version.");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote device is missing a vendor-supplied security patch."
  );
  script_set_attribute(
    attribute:"description",
    value:
"CVE-2020-12662

Unbound before 1.10.1 has Insufficient Control of Network Message
Volume, aka an 'NXNSAttack' issue. This is triggered by random
subdomains in the NSDNAME in NS records.

CVE-2020-12663 Unbound before 1.10.1 has an infinite loop via
malformed DNS answers received from upstream servers.

Impact

There are three types of DNS cache configurations available on the
BIG-IP system: a transparent cache, a resolver cache, and a validating
resolver cache. Only BIG-IP systems licensed for DNS services and
using the DNS Cache feature are vulnerable.

Notes :

The DNS Cache feature is available only when you licensethe BIG-IP
systemfor DNS Services, but you do NOT have to provisionthe BIG-IP GTM
or BIG-IP DNS moduleon your BIG-IP system.

Starting with BIG-IP 12.0.0, F5 renamed BIG-IP GTM to BIG-IP DNS.

DNS Express does not use Unbound and is not vulnerable to either
CVE-2020-12662 or CVE-2020-12663.

CVE-2020-12662

When the DNS Cache feature is enabled on the BIG-IP system, an
attacker may exploit this vulnerability to generate a large number of
communications between the BIG-IP system and the victim's
authoritative DNS server to cause a denial-of-service (DoS) attack.

Note : For more information about NXNSAttack, refer to the NXNSAttack
research paper.

CVE-2020-12663

A remote attacker may be able to perform a DoS attack on a DNS cache
configured on the BIG-IP system by causing Unbound to become
unresponsive."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nxnsattack.com/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://support.f5.com/csp/article/K37661551"
  );
  script_set_attribute(
    attribute:"solution",
    value:
"Upgrade to one of the non-vulnerable versions listed in the F5
Solution K37661551."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:f5:big-ip_global_traffic_manager");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:f5:big-ip");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/05/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/06/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/07/09");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2020-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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

sol = "K37661551";
vmatrix = make_array();

if (report_paranoia < 2) audit(AUDIT_PARANOID);

# GTM
vmatrix["GTM"] = make_array();
vmatrix["GTM"]["affected"  ] = make_list("15.0.0-15.1.0","14.1.0-14.1.2","13.1.0-13.1.3","12.1.0-12.1.5","11.6.1-11.6.5");
vmatrix["GTM"]["unaffected"] = make_list("16.0.0","15.1.0.5","14.1.2.7","13.1.3.5","12.1.6","11.6.5.3");


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
  else audit(AUDIT_HOST_NOT, "running the affected module GTM");
}
