#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2009:1341. The text 
# itself is copyright (C) Red Hat, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(63894);
  script_version("1.14");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2008-4579", "CVE-2008-6552");
  script_bugtraq_id(31904, 32179);
  script_xref(name:"RHSA", value:"2009:1341");

  script_name(english:"RHEL 5 : cman (RHSA-2009:1341)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated cman packages that fix several security issues, various bugs,
and add enhancements are now available for Red Hat Enterprise Linux 5.

This update has been rated as having low security impact by the Red
Hat Security Response Team.

The Cluster Manager (cman) utility provides services for managing a
Linux cluster.

Multiple insecure temporary file use flaws were found in
fence_apc_snmp and ccs_tool. A local attacker could use these flaws to
overwrite an arbitrary file writable by a victim running those
utilities (typically root) with the output of the utilities via a
symbolic link attack. (CVE-2008-4579, CVE-2008-6552)

Bug fixes :

* a buffer could overflow if cluster.conf had more than 52 entries per
block inside the <cman> block. The limit is now 1024.

* the output of the group_tool dump subcommands were NULL padded.

* using device='' instead of label='' no longer causes qdiskd to
incorrectly exit.

* the IPMI fencing agent has been modified to time out after 10
seconds. It is also now possible to specify a different timeout value
with the '-t' option.

* the IPMI fencing agent now allows punctuation in passwords.

* quickly starting and stopping the cman service no longer causes the
cluster membership to become inconsistent across the cluster.

* an issue with lock syncing caused 'receive_own from' errors to be
logged to '/var/log/messages'.

* an issue which caused gfs_controld to segfault when mounting
hundreds of file systems has been fixed.

* the LPAR fencing agent now properly reports status when an LPAR is
in Open Firmware mode.

* the LPAR fencing agent now works properly with systems using the
Integrated Virtualization Manager (IVM).

* the APC SNMP fencing agent now properly recognizes outletStatusOn
and outletStatusOff return codes from the SNMP agent.

* the WTI fencing agent can now connect to fencing devices with no
password.

* the rps-10 fencing agent now properly performs a reboot when run
with no options.

* the IPMI fencing agent now supports different cipher types with the
'-C' option.

* qdisk now properly scans devices and partitions.

* cman now checks to see if a new node has state to prevent killing
the first node during cluster setup.

* 'service qdiskd start' now works properly.

* the McData fence agent now works properly with the McData Sphereon
4500 Fabric Switch.

* the Egenera fence agent can now specify an SSH login name.

* the APC fence agent now works with non-admin accounts when using the
3.5.x firmware.

* fence_xvmd now tries two methods to reboot a virtual machine.

* connections to OpenAIS are now allowed from unprivileged CPG clients
with the user and group of 'ais'.

* groupd no longer allows the default fence domain to be '0', which
previously caused rgmanager to hang. Now, rgmanager no longer hangs.

* the RSA fence agent now supports SSH enabled RSA II devices.

* the DRAC fence agent now works with the Integrated Dell Remote
Access Controller (iDRAC) on Dell PowerEdge M600 blade servers.

* fixed a memory leak in cman.

* qdisk now displays a warning if more than one label is found with
the same name.

* the DRAC5 fencing agent now shows proper usage instructions for the
'-D' option.

* cman no longer uses the wrong node name when getnameinfo() fails.

* the SCSI fence agent now verifies that sg_persist is installed.

* the DRAC5 fencing agent now properly handles modulename.

* QDisk now logs warning messages if it appears its I/O to shared
storage is hung.

* fence_apc no longer fails with a pexpect exception.

* removing a node from the cluster using 'cman_tool leave remove' now
properly reduces the expected_votes and quorum.

* a semaphore leak in cman has been fixed.

* 'cman_tool nodes -F name' no longer segfaults when a node is out of
membership.

Enhancements :

* support for: ePowerSwitch 8+ and LPAR/HMC v3 devices, Cisco MDS 9124
and MDS 9134 SAN switches, the virsh fencing agent, and broadcast
communication with cman.

* fence_scsi limitations added to fence_scsi man page.

Users of cman are advised to upgrade to these updated packages, which
resolve these issues and add these enhancements."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2008-4579"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2008-6552"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/errata/RHSA-2009:1341"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected cman and / or cman-devel packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(59);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:cman");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:cman-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:5");

  script_set_attribute(attribute:"vuln_publication_date", value:"2008/10/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2009/09/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/01/24");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"Red Hat Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/RedHat/release", "Host/RedHat/rpm-list", "Host/cpu");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || "Red Hat" >!< release) audit(AUDIT_OS_NOT, "Red Hat");
os_ver = pregmatch(pattern: "Red Hat Enterprise Linux.*release ([0-9]+(\.[0-9]+)?)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Red Hat");
os_ver = os_ver[1];
if (! preg(pattern:"^5([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 5.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2009:1341";
  yum_report = redhat_generate_yum_updateinfo_report(rhsa:rhsa);
  if (!empty_or_null(yum_report))
  {
    security_report_v4(
      port       : 0,
      severity   : SECURITY_WARNING,
      extra      : yum_report 
    );
    exit(0);
  }
  else
  {
    audit_message = "affected by Red Hat security advisory " + rhsa;
    audit(AUDIT_OS_NOT, audit_message);
  }
}
else
{
  flag = 0;
  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"cman-2.0.115-1.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"cman-2.0.115-1.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"cman-2.0.115-1.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"cman-devel-2.0.115-1.el5")) flag++;

  if (flag)
  {
    security_report_v4(
      port       : 0,
      severity   : SECURITY_WARNING,
      extra      : rpm_report_get() + redhat_report_package_caveat()
    );
    exit(0);
  }
  else
  {
    tested = pkg_tests_get();
    if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "cman / cman-devel");
  }
}
