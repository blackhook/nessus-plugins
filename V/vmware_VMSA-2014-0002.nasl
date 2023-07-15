#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from VMware Security Advisory 2014-0002. 
# The text itself is copyright (C) VMware Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(72958);
  script_version("1.18");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/06");

  script_cve_id("CVE-2013-4332", "CVE-2013-5211");
  script_bugtraq_id(61310, 62324, 63079, 63082, 63089, 63095, 63098, 63101, 63102, 63103, 63106, 63110, 63111, 63112, 63115, 63118, 63120, 63121, 63122, 63124, 63126, 63127, 63128, 63129, 63130, 63131, 63132, 63133, 63134, 63135, 63136, 63137, 63139, 63140, 63141, 63142, 63143, 63144, 63145, 63146, 63147, 63148, 63149, 63150, 63151, 63152, 63153, 63154, 63155, 63156, 63157, 63158, 64692);
  script_xref(name:"VMSA", value:"2014-0002");

  script_name(english:"VMSA-2014-0002 : VMware vSphere updates to third-party libraries");
  script_summary(english:"Checks esxupdate output for the patches");

  script_set_attribute(
    attribute:"synopsis", 
    value:
"The remote VMware ESXi / ESX host is missing one or more
security-related patches."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"a. DDoS vulnerability in NTP third-party libraries

   The NTP daemon has a DDoS vulnerability in the handling of the
   'monlist' command. An attacker may send a forged request to a
   vulnerable NTP server resulting in an amplified response to the
   intended target of the DDoS attack. 
   
   Mitigation

   Mitigation for this issue is documented in VMware Knowledge Base
   article 2070193. This article also documents when vSphere 
   products are affected.

   The Common Vulnerabilities and Exposures project (cve.mitre.org)
   has assigned the name CVE-2013-5211 to this issue.

  b. Update to ESXi glibc package

  The ESXi glibc package is updated to version
  glibc-2.5-118.el5_10.2 to resolve a security issue.

  The Common Vulnerabilities and Exposures project (cve.mitre.org)
  has assigned the name CVE-2013-4332 to this issue.

  c. vCenter and Update Manager, Oracle JRE 1.7 Update 45
   
  Oracle JRE is updated to version JRE 1.7 Update 45, which
  addresses multiple security issues that existed in earlier
  releases of Oracle JRE. 

  Oracle has documented the CVE identifiers that are addressed
  in JRE 1.7.0 update 45 in the Oracle Java SE Critical Patch 
  Update Advisory of October 2013. The References section provides
  a link to this advisory."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.vmware.com/pipermail/security-announce/2014/000281.html"
  );
  script_set_attribute(attribute:"solution", value:"Apply the missing patches.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:vmware:esx:4.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:vmware:esx:4.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:vmware:esxi:4.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:vmware:esxi:4.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:vmware:esxi:5.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:vmware:esxi:5.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:vmware:esxi:5.5");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/03/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/03/12");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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


init_esx_check(date:"2014-03-11");
flag = 0;


if (esx_check(ver:"ESX 4.0", patch:"ESX400-201404402-SG")) flag++;

if (esx_check(ver:"ESX 4.1", patch:"ESX410-201404402-SG")) flag++;

if (esx_check(ver:"ESXi 4.0", patch:"ESXi400-201404401-SG")) flag++;

if (esx_check(ver:"ESXi 4.1", patch:"ESXi410-201404401-SG")) flag++;

if (esx_check(ver:"ESXi 5.0", vib:"VMware:tools-light:5.0.0-3.47.1749766")) flag++;

if (esx_check(ver:"ESXi 5.1", vib:"VMware:esx-base:5.1.0-2.27.1743201")) flag++;
if (esx_check(ver:"ESXi 5.1", vib:"VMware:esx-tboot:5.1.0-2.23.1483097")) flag++;
if (esx_check(ver:"ESXi 5.1", vib:"VMware:misc-drivers:5.1.0-2.23.1483097")) flag++;

if (esx_check(ver:"ESXi 5.5", vib:"VMware:esx-base:5.5.0-0.14.1598313")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:esx_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
