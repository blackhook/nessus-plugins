#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from VMware Security Advisory 2013-0015. 
# The text itself is copyright (C) VMware Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(71245);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/06");

  script_cve_id("CVE-2012-2372", "CVE-2012-3552", "CVE-2013-0791", "CVE-2013-1620", "CVE-2013-2147", "CVE-2013-2164", "CVE-2013-2206", "CVE-2013-2224", "CVE-2013-2232", "CVE-2013-2234", "CVE-2013-2237");
  script_bugtraq_id(54062, 55359, 57777, 58826, 60280, 60375, 60715, 60858, 60874, 60893, 60953);
  script_xref(name:"VMSA", value:"2013-0015");

  script_name(english:"VMSA-2013-0015 : VMware ESX updates to third-party libraries");
  script_summary(english:"Checks esxupdate output for the patches");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote VMware ESX host is missing one or more security-related
patches."
  );
  script_set_attribute(
    attribute:"description",
    value:
"a. Update to ESX service console kernel

The ESX service console kernel is updated to resolve multiple
security issues.

The Common Vulnerabilities and Exposures project (cve.mitre.org)
has assigned the names CVE-2012-2372, CVE-2012-3552, CVE-2013-2147,
CVE-2013-2164, CVE-2013-2206, CVE-2013-2224, CVE-2013-2234, 
CVE-2013-2237, CVE-2013-2232 to these issues.

b. Update to ESX service console NSPR and NSS

This patch updates the ESX service console Netscape Portable 
Runtime (NSPR) and Network Security Services (NSS) RPMs to resolve
multiple security issues. 

The Common Vulnerabilities and Exposures project (cve.mitre.org)
has assigned the names CVE-2013-0791 and CVE-2013-1620 to these 
issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.vmware.com/pipermail/security-announce/2013/000227.html"
  );
  script_set_attribute(attribute:"solution", value:"Apply the missing patches.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:vmware:esx:4.1");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/10/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/12/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/12/06");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"VMware ESX Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/VMware/release", "Host/VMware/version");
  script_require_ports("Host/VMware/esxupdate", "Host/VMware/esxcli_software_vibs");

  exit(0);
}


include("audit.inc");
include("vmware_esx_packages.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/VMware/release")) audit(AUDIT_OS_NOT, "VMware ESX / ESXi");
if (
  !get_kb_item("Host/VMware/esxcli_software_vibs") &&
  !get_kb_item("Host/VMware/esxupdate")
) audit(AUDIT_PACKAGE_LIST_MISSING);


init_esx_check(date:"2013-12-05");
flag = 0;


if (
  esx_check(
    ver           : "ESX 4.1",
    patch         : "ESX410-201312401-SG",
    patch_updates : make_list("ESX410-201404401-SG")
  )
) flag++;
if (esx_check(ver:"ESX 4.1", patch:"ESX410-201312403-SG")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:esx_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
