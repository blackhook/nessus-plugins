#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(71197);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2013-0281");

  script_name(english:"Scientific Linux Security Update : pacemaker on SL6.x i386/x86_64 (20131121)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:
"The remote Scientific Linux host is missing one or more security
updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"A denial of service flaw was found in the way Pacemaker performed
authentication and processing of remote connections in certain
circumstances. When Pacemaker was configured to allow remote Cluster
Information Base (CIB) configuration or resource management, a remote
attacker could use this flaw to cause Pacemaker to block indefinitely
(preventing it from serving other requests). (CVE-2013-0281)

Note: The default Pacemaker configuration in Scientific Linux 6 has
the remote CIB management functionality disabled.

The pacemaker package has been upgraded to upstream version 1.1.10,
which provides a number of bug fixes and enhancements over the
previous version :

  - Pacemaker no longer assumes unknown cman nodes are
    safely stopped.

  - The core dump file now converts all exit codes into
    positive 'errno' values.

  - Pacemaker ensures a return to a stable state after too
    many fencing failures, and initiates a shutdown if a
    node claimed to be fenced is still active.

  - The crm_error tool adds the ability to list and print
    error symbols.

  - The crm_resource command allows individual resources to
    be reprobed, and implements the '--ban' option for
    moving resources away from nodes. The ' --clear' option
    has replaced the '--unmove' option. Also, crm_resource
    now supports OCF tracing when using the '--force'
    option.

  - The IPC mechanism restores the ability for members of
    the haclient group to connect to the cluster.

  - The Policy Engine daemon allows active nodes in the
    current membership to be fenced without quorum.

  - Policy Engine now suppresses meaningless IDs when
    displaying anonymous clone status, supports maintenance
    mode for a single node, and correctly handles the
    recovered resources before they are operated on.

  - XML configuration files are now checked for non-printing
    characters and replaced with their octal equivalent when
    exporting XML text. Also, a more reliable buffer
    allocation strategy has been implemented to prevent
    lockups.

Additional bug fixes :

  - The 'crm_resource --move' command was designed for
    atomic resources and could not handle resources on
    clones, masters, or slaves present on multiple nodes.
    Consequently, crm_resource could not obtain enough
    information to move a resource and did not perform any
    action. The '--ban' and '--clear' options have been
    added to allow the administrator to instruct the cluster
    unambiguously. Clone, master, and slave resources can
    now be navigated within the cluster as expected.

  - The hacluster user account did not have a user
    identification (UID) or group identification (GID)
    number reserved on the system. Thus, UID and GID values
    were picked randomly during the installation process.
    The UID and GID number 189 was reserved for hacluster
    and is now used consistently for all installations.

  - Certain clusters used node host names that did not match
    the output of the 'uname -n' command. Thus, the default
    node name used by the crm_standby and crm_failcount
    commands was incorrect and caused the cluster to ignore
    the update by the administrator. The crm_node command is
    now used instead of the uname utility in helper scripts.
    As a result, the cluster behaves as expected.

  - Due to incorrect return code handling, internal recovery
    logic of the crm_mon utility was not executed when a
    configuration updated failed to apply, leading to an
    assertion failure. Return codes are now checked
    correctly, and the recovery of an expected error state
    is now handled transparently.

  - cman's automatic unfencing feature failed when combined
    with Pacemaker. Support for automated unfencing in
    Pacemaker has been added, and the unwanted behavior no
    longer occurs."
  );
  # https://listserv.fnal.gov/scripts/wa.exe?A2=ind1312&L=scientific-linux-errata&T=0&P=691
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?eccb4dcc"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:clusterlib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:clusterlib-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:cman");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:corosync");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:corosynclib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:corosynclib-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:fence-agents");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:gfs2-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libqb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libqb-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:luci");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:pacemaker");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:pacemaker-cli");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:pacemaker-cluster-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:pacemaker-cts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:pacemaker-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:pacemaker-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:pacemaker-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:pacemaker-libs-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:pacemaker-remote");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/11/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/11/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/12/04");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"Scientific Linux Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/RedHat/release", "Host/RedHat/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || "Scientific Linux " >!< release) audit(AUDIT_HOST_NOT, "running Scientific Linux");
os_ver = pregmatch(pattern: "Scientific Linux.*release ([0-9]+(\.[0-9]+)?)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Scientific Linux");
os_ver = os_ver[1];
if (! preg(pattern:"^6([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Scientific Linux 6.x", "Scientific Linux " + os_ver);
if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu >!< "x86_64" && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Scientific Linux", cpu);


flag = 0;
if (rpm_check(release:"SL6", reference:"clusterlib-3.0.12.1-59.el6")) flag++;
if (rpm_check(release:"SL6", reference:"clusterlib-devel-3.0.12.1-59.el6")) flag++;
if (rpm_check(release:"SL6", reference:"cman-3.0.12.1-59.el6")) flag++;
if (rpm_check(release:"SL6", reference:"corosync-1.4.1-17.el6")) flag++;
if (rpm_check(release:"SL6", reference:"corosynclib-1.4.1-17.el6")) flag++;
if (rpm_check(release:"SL6", reference:"corosynclib-devel-1.4.1-17.el6")) flag++;
if (rpm_check(release:"SL6", reference:"fence-agents-3.1.5-35.el6")) flag++;
if (rpm_check(release:"SL6", reference:"gfs2-utils-3.0.12.1-59.el6")) flag++;
if (rpm_check(release:"SL6", reference:"libqb-0.16.0-2.el6")) flag++;
if (rpm_check(release:"SL6", reference:"libqb-devel-0.16.0-2.el6")) flag++;
if (rpm_check(release:"SL6", reference:"luci-0.26.0-48.el6")) flag++;
if (rpm_check(release:"SL6", reference:"pacemaker-1.1.10-14.el6")) flag++;
if (rpm_check(release:"SL6", reference:"pacemaker-cli-1.1.10-14.el6")) flag++;
if (rpm_check(release:"SL6", reference:"pacemaker-cluster-libs-1.1.10-14.el6")) flag++;
if (rpm_check(release:"SL6", reference:"pacemaker-cts-1.1.10-14.el6")) flag++;
if (rpm_check(release:"SL6", reference:"pacemaker-debuginfo-1.1.10-14.el6")) flag++;
if (rpm_check(release:"SL6", reference:"pacemaker-doc-1.1.10-14.el6")) flag++;
if (rpm_check(release:"SL6", reference:"pacemaker-libs-1.1.10-14.el6")) flag++;
if (rpm_check(release:"SL6", reference:"pacemaker-libs-devel-1.1.10-14.el6")) flag++;
if (rpm_check(release:"SL6", reference:"pacemaker-remote-1.1.10-14.el6")) flag++;


if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_WARNING,
    extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "clusterlib / clusterlib-devel / cman / corosync / corosynclib / etc");
}
