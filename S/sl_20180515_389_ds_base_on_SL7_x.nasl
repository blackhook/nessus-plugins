#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(109848);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/02/24");

  script_cve_id("CVE-2018-1089");

  script_name(english:"Scientific Linux Security Update : 389-ds-base on SL7.x x86_64 (20180515)");
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
"Security Fix(es) :

  - 389-ds-base: ns-slapd crash via large filter value in
    ldapsearch (CVE-2018-1089)

Bug Fix(es) :

  - Indexing tasks in Directory Server contain the
    nsTaskStatus attribute to monitor whether the task is
    completed and the database is ready to receive updates.
    Before this update, the server set the value that
    indexing had completed before the database was ready to
    receive updates. Applications which monitor nsTaskStatus
    could start sending updates as soon as indexing
    completed, but before the database was ready. As a
    consequence, the server rejected updates with an
    UNWILLING_TO_PERFORM error. The problem has been fixed.
    As a result, the nsTaskStatus attribute now shows that
    indexing is completed after the database is ready to
    receive updates.

  - Previously, Directory Server did not remember when the
    first operation, bind, or a connection was started. As a
    consequence, the server applied in certain situations
    anonymous resource limits to an authenticated client.
    With this update, Directory Server properly marks
    authenticated client connections. As a result, it
    applies the correct resource limits, and authenticated
    clients no longer get randomly restricted by anonymous
    resource limits.

  - When debug replication logging is enabled, Directory
    Server incorrectly logged an error that updating the
    replica update vector (RUV) failed when in fact the
    update succeeded. The problem has been fixed, and the
    server no longer logs an error if updating the RUV
    succeeds.

  - This update adds the -W option to the ds-replcheck
    utility. With this option, ds-replcheck asks for the
    password, similar to OpenLDAP utilities. As a result,
    the password is not stored in the shell's history file
    when the -W option is used.

  - If an administrator moves a group in Directory Server
    from one subtree to another, the memberOf plug-in
    deletes the memberOf attribute with the old value and
    adds a new memberOf attribute with the new group's
    distinguished name (DN) in affected user entries.
    Previously, if the old subtree was not within the scope
    of the memberOf plug-in, deleting the old memberOf
    attribute failed because the values did not exist. As a
    consequence, the plug-in did not add the new memberOf
    value, and the user entry contained an incorrect
    memberOf value. With this update, the plug-in now checks
    the return code when deleting the old value. If the
    return code is 'no such value', the plug-in only adds
    the new memberOf value. As a result, the memberOf
    attribute information is correct.

  - In a Directory Server replication topology, updates are
    managed by using Change Sequence Numbers (CSN) based on
    time stamps. New CSNs must be higher than the highest
    CSN present in the relative update vector (RUV). In case
    the server generates a new CSN in the same second as the
    most recent CSN, the sequence number is increased to
    ensure that it is higher. However, if the most recent
    CSN and the new CSN were identical, the sequence number
    was not increased. In this situation, the new CSN was,
    except the replica ID, identical to the most recent one.
    As a consequence, a new update in the directory appeared
    in certain situations older than the most recent update.
    With this update, Directory Server increases the CSN if
    the sequence number is lower or equal to the most recent
    one. As a result, new updates are no longer considered
    older than the most recent data."
  );
  # https://listserv.fnal.gov/scripts/wa.exe?A2=ind1805&L=scientific-linux-errata&F=&S=&P=18513
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?cf6f1e8c"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:389-ds-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:389-ds-base-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:389-ds-base-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:389-ds-base-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:389-ds-base-snmp");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/05/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/05/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/05/16");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2018-2020 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"389-ds-base-1.3.7.5-21.el7_5")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"389-ds-base-debuginfo-1.3.7.5-21.el7_5")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"389-ds-base-devel-1.3.7.5-21.el7_5")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"389-ds-base-libs-1.3.7.5-21.el7_5")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"389-ds-base-snmp-1.3.7.5-21.el7_5")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "389-ds-base / 389-ds-base-debuginfo / 389-ds-base-devel / etc");
}
