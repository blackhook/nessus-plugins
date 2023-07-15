#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The package checks in this plugin were extracted from OracleVM
# Security Advisory OVMSA-2017-0159.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(104138);
  script_version("3.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_name(english:"OracleVM 3.2 : xen (OVMSA-2017-0159)");
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

  - The code of OVM3.2.9 is quite old, there is no
    get_page/put_page pair to protect the ownership and
    references of page table page which is mapped in
    emulate_map_dest. This patch fix it by adding get_page
    in emulate_gva_to_mfn to match put_page in
    xsa219-4.5.patch so that it works.

  - From: Jan Beulich Subject: gnttab: also validate PTE
    permissions upon destroy/replace In order for PTE
    handling to match up with the reference counting done by
    common code, presence and writability of grant mapping
    PTEs must also be taken into account  validating just
    the frame number is not enough. This is in particular
    relevant if a guest fiddles with grant PTEs via
    non-grant hypercalls. Note that the flags being passed
    to replace_grant_host_mapping already happen to be those
    of the existing mapping, so no new function parameter is
    needed. This is XSA-234.

  - From: Juergen Gross Subject: tools/xenstore: don't
    unlink connection object twice A connection object of a
    domain with associated stubdom has two parents: the
    domain and the stubdom. When cleaning up the list of
    active domains in domain_cleanup make sure not to unlink
    the connection twice from the same domain. This could
    happen when the domain and its stubdom are being
    destroyed at the same time leading to the domain loop
    being entered twice. Additionally don't use talloc_free
    in this case as it will remove a random parent link,
    leading eventually to a memory leak. Use talloc_unlink
    instead specifying the context from which the connection
    object should be removed. This is XSA-233.

  - From: George Dunlap Subject: xen/mm: make sure node is
    less than MAX_NUMNODES The output of
    MEMF_get_node(memflags) can be as large as nodeid_t can
    hold (currently 255). This is then used as an index to
    arrays of size MAX_NUMNODE, which is 64 on x86 and 1 on
    ARM, can be passed in by an untrusted guest (via
    memory_exchange and increase_reservation) and is not
    currently bounds-checked. Check the value in
    page_alloc.c before using it, and also check the value
    in the hypercall call sites and return -EINVAL if
    appropriate. Don't permit domains other than the
    hardware or control domain to allocate node-constrained
    memory. This is XSA-231.

    Conflict: xen/common/memory.c Use IS_PRIV instead of
    is_hardware_domain and is_control_domain in original
    patch."
  );
  # https://oss.oracle.com/pipermail/oraclevm-errata/2017-October/000789.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?6376c0c5"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected xen / xen-devel / xen-tools packages."
  );
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:vm:xen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:vm:xen-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:vm:xen-tools");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:vm_server:3.2");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/10/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/10/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/10/25");
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
if (! preg(pattern:"^OVS" + "3\.2" + "(\.[0-9]|$)", string:release)) audit(AUDIT_OS_NOT, "OracleVM 3.2", "OracleVM " + release);
if (!get_kb_item("Host/OracleVM/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "OracleVM", cpu);
if ("x86_64" >!< cpu) audit(AUDIT_ARCH_NOT, "x86_64", cpu);

flag = 0;
if (rpm_check(release:"OVS3.2", reference:"xen-4.1.3-25.el5.223.86")) flag++;
if (rpm_check(release:"OVS3.2", reference:"xen-devel-4.1.3-25.el5.223.86")) flag++;
if (rpm_check(release:"OVS3.2", reference:"xen-tools-4.1.3-25.el5.223.86")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "xen / xen-devel / xen-tools");
}
