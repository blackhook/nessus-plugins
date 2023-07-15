#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory FEDORA-2018-e31f52c5ee.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(109825);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/06");

  script_xref(name:"FEDORA", value:"2018-e31f52c5ee");

  script_name(english:"Fedora 27 : mysql-mmm (2018-e31f52c5ee)");
  script_summary(english:"Checks rpm output for the updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"# Multi-Master Replication Manager for MySQL mmm_agentd Remote Command
Injection Vulnerabilities

This update adds data sanitization to inputs for the mmm agent.

Multiple exploitable remote command injection vulnerabilities exist in
the MySQL Master-Master Replication Manager (MMM) mmm_agentd daemon
2.2.1. mmm_agentd commonly runs with root privileges and does not
require authentication by default. A specially crafted MMM protocol
message can cause a shell command injection resulting in arbitrary
command execution with the privileges of the mmm_agentd process. An
attacker that can initiate a TCP session with mmm_agentd can trigger
these vulnerabilities.

The impact of these vulnerabilities can be lessened by configuring
mmm_agentd to require TLS mutual authentication and by using network
ACLs to prevent hosts other than legitimate mmm_mond hosts from
accessing mmm_agentd.

For example on Linux iptables rules can be used to block access to the
port mmm_agent is listening on from all hosts except the mmm_monitor.

The configuration of ssl can be used where firewall rules are not
practical. See Socket Documentation
http://mysql-mmm.org/mysql-mmm.html#SEC58

Add to mmm_common.conf

<socket> type ssl cert_file /etc/ssl/certs/www.example.com.bundle.crt
key_file /etc/ssl/certs/www.example.com.key ca_file
/etc/ssl/certs/ca-bundle.crt # or ca-certificates.crt </socket>

Now only those with access to the private key can send commands.
Whilst your web server certificate will do the job, you may consider
registering a dedicated certificate just for this task.

NOTE: By now there are a some good alternatives to MySQL-MMM. Maybe
you want to check out Galera Cluster which is part of MariaDB Galera
Cluster and Percona XtraDB Cluster.

- http://mysql-mmm.org

- http://galeracluster.com/

- https://mariadb.com/kb/en/library/what-is-mariadb-galera-cluster/

- https://www.percona.com/software/mysql-database/percona-xtradb-cluster

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora update system website.
Tenable has attempted to automatically clean and format it as much as
possible without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bodhi.fedoraproject.org/updates/FEDORA-2018-e31f52c5ee"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected mysql-mmm package."
  );
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:mysql-mmm");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:27");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/05/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/05/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/05/16");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2018-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"Fedora Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/RedHat/release", "Host/RedHat/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || "Fedora" >!< release) audit(AUDIT_OS_NOT, "Fedora");
os_ver = pregmatch(pattern: "Fedora.*release ([0-9]+)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Fedora");
os_ver = os_ver[1];
if (! preg(pattern:"^27([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 27", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);


flag = 0;
if (rpm_check(release:"FC27", reference:"mysql-mmm-2.2.1-20.fc27")) flag++;


if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_HOLE,
    extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "mysql-mmm");
}
