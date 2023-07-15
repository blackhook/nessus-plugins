#
# (C) Tenable Network Security, Inc.
#
# The package checks in this plugin were extracted from OracleVM
# Security Advisory OVMSA-2018-0225.
#

include("compat.inc");

if (description)
{
  script_id(110305);
  script_version("1.3");
  script_cvs_date("Date: 2019/09/27 13:00:35");

  script_cve_id("CVE-2017-17563", "CVE-2017-17564", "CVE-2017-17565", "CVE-2017-17566");

  script_name(english:"OracleVM 3.2 : xen (OVMSA-2018-0225)");
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

  - From: Jan Beulich Subject: x86/paging: don't
    unconditionally BUG on finding SHARED_M2P_ENTRY PV
    guests can fully control the values written into the
    P2M. This is XSA-251. (CVE-2017-17565)

  - From: Jan Beulich Subject: x86/shadow: fix ref-counting
    error handling The old-Linux handling in shadow_set_l4e
    mistakenly ORed together the results of sh_get_ref and
    sh_pin. As the latter failing is not a correctness
    problem, simply ignore its return value. In
    sh_set_toplevel_shadow a failing sh_get_ref must not be
    accompanied by installing the entry, despite the domain
    being crashed. This is XSA-250. (CVE-2017-17564)

  - From: Jan Beulich Subject: x86/shadow: fix refcount
    overflow check Commit c385d27079 ('x86 shadow: for
    multi-page shadows, explicitly track the first page')
    reduced the refcount width to 25, without adjusting the
    overflow check. Eliminate the disconnect by using a
    manifest constant. Interestingly, up to commit
    047782fa01 ('Out-of-sync L1 shadows: OOS snapshot') the
    refcount was 27 bits wide, yet the check was already
    using 26. This is XSA-249. v2: Simplify expression back
    to the style it was. (CVE-2017-17563)

  - From: Jan Beulich Subject: x86/mm: don't wrongly set
    page ownership PV domains can obtain mappings of any
    pages owned by the correct domain, including ones that
    aren't actually assigned as 'normal' RAM, but used by
    Xen internally. At the moment such 'internal' pages
    marked as owned by a guest include pages used to track
    logdirty bits, as well as p2m pages and the 'unpaged
    pagetable' for HVM guests. Since the PV memory
    management and shadow code conflict in their use of
    struct page_info fields, and since shadow code is being
    used for log-dirty handling for PV domains, pages coming
    from the shadow pool must, for PV domains, not have the
    domain set as their owner. While the change could be
    done conditionally for just the PV case in shadow code,
    do it unconditionally (and for consistency also for
    HAP), just to be on the safe side. There's one special
    case though for shadow code: The page table used for
    running a HVM guest in unpaged mode is subject to
    get_page (in set_shadow_status) and hence must have its
    owner set. This is XSA-248.

    Conflict: xen/arch/x86/mm/hap/hap.c
    xen/arch/x86/mm/shadow/common.c (CVE-2017-17566)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/oraclevm-errata/2018-June/000860.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected xen / xen-devel / xen-tools packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:H/PR:L/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:vm:xen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:vm:xen-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:vm:xen-tools");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:vm_server:3.2");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/12/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/06/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/06/04");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2018-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (rpm_check(release:"OVS3.2", reference:"xen-4.1.3-25.el5.223.170")) flag++;
if (rpm_check(release:"OVS3.2", reference:"xen-devel-4.1.3-25.el5.223.170")) flag++;
if (rpm_check(release:"OVS3.2", reference:"xen-tools-4.1.3-25.el5.223.170")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "xen / xen-devel / xen-tools");
}
