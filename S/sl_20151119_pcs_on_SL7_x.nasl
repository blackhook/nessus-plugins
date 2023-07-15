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
  script_id(87569);
  script_version("2.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2015-3225");

  script_name(english:"Scientific Linux Security Update : pcs on SL7.x x86_64 (20151119)");
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
"A flaw was found in a way Rack processed parameters of incoming
requests. An attacker could use this flaw to send a crafted request
that would cause an application using Rack to crash. (CVE-2015-3225)

The pcs package has been upgraded to upstream version 0.9.143, which
provides a number of bug fixes and enhancements over the previous
version.

  - The pcs resource move and pcs resource ban commands now
    display a warning message to clarify the commands'
    behavior

  - New command to move a Pacemaker resource to its
    preferred node

This update also fixes the following bugs :

  - Before this update, a bug caused location, ordering, and
    colocation constraints related to a resource group to be
    removed when removing any resource from that group. This
    bug has been fixed, and the constraints are now
    preserved until the group has no resources left, and is
    removed.

  - Previously, when a user disabled a resource clone or
    multi-state resource, and then later enabled a primitive
    resource within it, the clone or multi-state resource
    remained disabled. With this update, enabling a resource
    within a disabled clone or multi-state resource enables
    it.

  - When the web UI displayed a list of resource attributes,
    a bug caused the list to be truncated at the first '='
    character. This update fixes the bug and now the web UI
    displays lists of resource attributes correctly.

  - The documentation for the 'pcs stonith confirm' command
    was not clear. This could lead to incorrect usage of the
    command, which could in turn cause data corruption. With
    this update, the documentation has been improved and the
    'pcs stonith confirm' command is now more clearly
    explained.

  - Previously, if there were any unauthenticated nodes,
    creating a new cluster, adding a node to an existing
    cluster, or adding a cluster to the web UI failed with
    the message 'Node is not authenticated'. With this
    update, when the web UI detects a problem with
    authentication, the web UI displays a dialog to
    authenticate nodes as necessary.

  - Previously, the web UI displayed only primitive
    resources. Thus there was no way to set attributes,
    constraints and other properties separately for a parent
    resource and a child resource. This has now been fixed,
    and resources are displayed in a tree structure, meaning
    all resource elements can be viewed and edited
    independently.

In addition, this update adds the following enhancements :

  - A dashboard has been added which shows the status of
    clusters in the web UI. Previously, it was not possible
    to view all important information about clusters in one
    place. Now, a dashboard showing the status of clusters
    has been added to the main page of the web UI.

  - With this update, the pcsd daemon automatically
    synchronizes pcsd configuration across a cluster. This
    enables the web UI to be run from any node, allowing
    management even if any particular node is down.

  - The web UI can now be used to set permissions for users
    and groups on a cluster. This allows users and groups to
    have their access restricted to certain operations on
    certain clusters."
  );
  # https://listserv.fnal.gov/scripts/wa.exe?A2=ind1512&L=scientific-linux-errata&F=&S=&P=14243
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?bdc49286"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected pcs and / or pcs-debuginfo packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:pcs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:pcs-debuginfo");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/07/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/11/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/12/22");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (! preg(pattern:"^7([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Scientific Linux 7.x", "Scientific Linux " + os_ver);
if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu >!< "x86_64" && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Scientific Linux", cpu);
if ("x86_64" >!< cpu) audit(AUDIT_ARCH_NOT, "x86_64", cpu);


flag = 0;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"pcs-0.9.143-15.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"pcs-debuginfo-0.9.143-15.el7")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "pcs / pcs-debuginfo");
}
