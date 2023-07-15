#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The package checks in this plugin were extracted from OracleVM
# Security Advisory OVMSA-2017-0177.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(105250);
  script_version("3.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2017-15592", "CVE-2017-17044", "CVE-2017-17045");

  script_name(english:"OracleVM 3.3 : xen (OVMSA-2017-0177)");
  script_summary(english:"Checks the RPM output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote OracleVM host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The remote OracleVM system is missing necessary patches to address
critical security updates :

  - Due to the history performance reason, we decide to
    disable PoD feature in old OVM product.XSA-246,XSA-247
    [bug 27121016] (CVE-2017-17044, CVE-2017-17045)

  - From 2a99aa99fc84a45f505f84802af56b006d14c52e Mon Sep 17
    00:00:00 2001 From: Andrew Cooper Date: Fri, 19 Aug 2016
    15:08:10 +0100 Subject: [PATCH] xen/physmap: Do not
    permit a guest to populate PoD pages for itself PoD is
    supposed to be entirely transparent to guest, but this
    interface has been left exposed for a long time. The use
    of PoD requires careful co-ordination by the toolstack
    with the XENMEM_[get,set]_pod_target hypercalls, and
    xenstore ballooning target. The best a guest can do
    without toolstack cooperation crash. Furthermore, there
    are combinations of features (e.g. c/s c63868ff 'libxl:
    disallow PCI device assignment for HVM guest when PoD is
    enabled') which a toolstack might wish to explicitly
    prohibit (in this case, because the two simply don't
    function in combination). In such cases, the guest
    mustn't be able to subvert the configuration chosen by
    the toolstack.

    Conflict: xen/common/memory.c

  - x86/shadow: correct SH_LINEAR mapping detection in
    sh_guess_wrmap The fix for XSA-243 / CVE-2017-15592 (c/s
    bf2b4eadcf379) introduced a change in behaviour for
    sh_guest_wrmap, where it had to cope with no shadow
    linear mapping being present. As the name suggests,
    guest_vtable is a mapping of the guests pagetable, not
    Xen's pagetable, meaning that it isn't the pagetable we
    need to check for the shadow linear slot in. The
    practical upshot is that a shadow HVM vcpu which
    switches into 4-level paging mode, with an L4 pagetable
    that contains a mapping which aliases Xen's
    SH_LINEAR_PT_VIRT_START will fool the safety check for
    whether a SHADOW_LINEAR mapping is present. As the check
    passes (when it should have failed), Xen subsequently
    falls over the missing mapping with a pagefault such as:
    (XEN) Pagetable walk from ffff8140a0503880: (XEN)
    L4[0x102] = 000000046c218063 ffffffffffffffff (XEN)
    L3[0x102] = 000000046c218063 ffffffffffffffff (XEN)
    L2[0x102] = 000000046c218063 ffffffffffffffff (XEN)
    L1[0x103] = 0000000000000000 ffffffffffffffff This is
    part of XSA-243. (CVE-2017-15592)"
  );
  # https://oss.oracle.com/pipermail/oraclevm-errata/2017-December/000809.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?32635f3b"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected xen / xen-tools packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:vm:xen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:vm:xen-tools");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:vm_server:3.3");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/10/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/12/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/12/14");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"OracleVM Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/OracleVM/release", "Host/OracleVM/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/OracleVM/release");
if (isnull(release) || "OVS" >!< release) audit(AUDIT_OS_NOT, "OracleVM");
if (! preg(pattern:"^OVS" + "3\.3" + "(\.[0-9]|$)", string:release)) audit(AUDIT_OS_NOT, "OracleVM 3.3", "OracleVM " + release);
if (!get_kb_item("Host/OracleVM/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "OracleVM", cpu);
if ("x86_64" >!< cpu) audit(AUDIT_ARCH_NOT, "x86_64", cpu);

flag = 0;
if (rpm_check(release:"OVS3.3", reference:"xen-4.3.0-55.el6.186.63")) flag++;
if (rpm_check(release:"OVS3.3", reference:"xen-tools-4.3.0-55.el6.186.63")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "xen / xen-tools");
}
