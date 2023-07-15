#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The package checks in this plugin were extracted from OracleVM
# Security Advisory OVMSA-2017-0148.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(102906);
  script_version("3.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2017-12135", "CVE-2017-12137", "CVE-2017-12855");

  script_name(english:"OracleVM 3.3 : xen (OVMSA-2017-0148)");
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

  - From: Jan Beulich Subject: gnttab: correct pin status
    fixup for copy Regardless of copy operations only
    setting GNTPIN_hst*, GNTPIN_dev* also need to be taken
    into account when deciding whether to clear
    _GTF_[read,writ]ing. At least for consistency with code
    elsewhere the read part better doesn't use any mask at
    all. This is XSA-230. (CVE-2017-12855)

  - From: Andrew Cooper Subject: grant_table: Default to v1,
    and disallow transitive grants The reference counting
    and locking discipline for transitive grants is broken.
    Their use is therefore declared out of security support.
    This is XSA-226. Transitive grants are expected to be
    unconditionally available with grant table v2. Hiding
    transitive grants alone is an ABI breakage for the
    guest. Modern versions of Linux and the Windows PV
    drivers use grant table v1, but older versions did use
    v2. In principle, disabling gnttab v2 entirely is the
    safer way to cause guests to avoid using transitive
    grants. However, some older guests which defaulted to
    using gnttab v2 don't tolerate falling back from v2 to
    v1 over migrate. This patch introduces a new command
    line option to control grant table behaviour. One
    suboption allows a choice of the maximum grant table
    version Xen will allow the guest to use, and defaults to
    v2. A different suboption independently controls whether
    transitive grants can be used. The default case is:
    gnttab=max_ver:2 To disable gnttab v2 entirely, use:
    gnttab=max_ver:1 To allow gnttab v2 and transitive
    grants, use: gnttab=max_ver:2,transitive

    Conflict: docs/misc/xen-command-line.markdown
    (CVE-2017-12135)

  - Revert wrong fix for xsa226 [bug 26567225]

  - From 3aab881c7331cf93ffd8d2f2dd9adfd18ed4fc99 Mon Sep 17
    00:00:00 2001 From: Andrew Cooper Date: Tue, 20 Jun 2017
    19:18:54 +0100 Subject: [PATCH] x86/grant: Disallow
    misaligned PTEs Pagetable entries must be aligned to
    function correctly. Disallow attempts from the guest to
    have a grant PTE created at a misaligned address, which
    would result in corruption of the L1 table with
    largely-guest-controlled values. This is XSA-227
    (CVE-2017-12137)

  - Prerequisite patch for xsa227-4.5.patch There is no
    macro ASSERT_UNREACHABLE before OVM3.4 which is needed
    by xsa227-4.5.patch This chunk is picked from upstream
    commit cacdb0faaa121ac8f792d5bd34cc6bc7c72d21da
    (CVE-2017-12137)

  - From: Jan Beulich Subject: gnttab: don't use possibly
    unbounded tail calls There is no guarantee that the
    compiler would actually translate them to branches
    instead of calls, so only ones with a known recursion
    limit are okay :

  - __release_grant_for_copy can call itself only once, as
    __acquire_grant_for_copy won't permit use of multi-level
    transitive grants,

  - __acquire_grant_for_copy is fine to call itself with the
    last argument false, as that prevents further recursion,

  - __acquire_grant_for_copy must not call itself to recover
    from an observed change to the active entry's pin count
    This is XSA-226. (CVE-2017-12135)

  - From 69549b08eb9bd3a525c07a97d952673a3d02c76a Mon Sep 17
    00:00:00 2001 From: Annie Li Date: Fri, 7 Jul 2017
    14:36:08 -0400 Subject: [PATCH] xen: increase default
    max grant frames and max maptrack frames Commit
    9dfba034e increase default max grant frames to 128 which
    is still not enough when the guest has more cpus and
    vbd/vif devices, so set it to 256. Also the default max
    maptrack frames needs to be increased accordingly."
  );
  # https://oss.oracle.com/pipermail/oraclevm-errata/2017-August/000774.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?e4f463c5"
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

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/08/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/08/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/09/01");
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
if (rpm_check(release:"OVS3.3", reference:"xen-4.3.0-55.el6.186.45")) flag++;
if (rpm_check(release:"OVS3.3", reference:"xen-tools-4.3.0-55.el6.186.45")) flag++;

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
