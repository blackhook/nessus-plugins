#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(141654);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/10/23");

  script_cve_id("CVE-2019-3695", "CVE-2019-3696");

  script_name(english:"Scientific Linux Security Update : pcp on SL7.x x86_64 (20201001)");
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

  - pcp: Local privilege escalation in pcp spec file %post
    section (CVE-2019-3695)

  - pcp: Local privilege escalation in pcp spec file through
    migrate_tempdirs (CVE-2019-3696)"
  );
  # https://listserv.fnal.gov/scripts/wa.exe?A2=ind2010&L=SCIENTIFIC-LINUX-ERRATA&P=11410
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?f2986d22"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:pcp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:pcp-conf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:pcp-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:pcp-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:pcp-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:pcp-export-pcp2elasticsearch");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:pcp-export-pcp2graphite");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:pcp-export-pcp2influxdb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:pcp-export-pcp2json");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:pcp-export-pcp2spark");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:pcp-export-pcp2xml");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:pcp-export-pcp2zabbix");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:pcp-export-zabbix-agent");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:pcp-gui");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:pcp-import-collectl2pcp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:pcp-import-ganglia2pcp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:pcp-import-iostat2pcp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:pcp-import-mrtg2pcp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:pcp-import-sar2pcp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:pcp-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:pcp-libs-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:pcp-manager");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:pcp-pmda-activemq");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:pcp-pmda-apache");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:pcp-pmda-bash");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:pcp-pmda-bcc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:pcp-pmda-bind2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:pcp-pmda-bonding");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:pcp-pmda-cifs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:pcp-pmda-cisco");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:pcp-pmda-dbping");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:pcp-pmda-dm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:pcp-pmda-docker");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:pcp-pmda-ds389");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:pcp-pmda-ds389log");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:pcp-pmda-elasticsearch");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:pcp-pmda-gfs2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:pcp-pmda-gluster");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:pcp-pmda-gpfs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:pcp-pmda-gpsd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:pcp-pmda-haproxy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:pcp-pmda-infiniband");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:pcp-pmda-json");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:pcp-pmda-libvirt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:pcp-pmda-lio");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:pcp-pmda-lmsensors");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:pcp-pmda-logger");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:pcp-pmda-lustre");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:pcp-pmda-lustrecomm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:pcp-pmda-mailq");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:pcp-pmda-memcache");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:pcp-pmda-mic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:pcp-pmda-mounts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:pcp-pmda-mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:pcp-pmda-named");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:pcp-pmda-netfilter");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:pcp-pmda-news");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:pcp-pmda-nfsclient");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:pcp-pmda-nginx");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:pcp-pmda-nvidia-gpu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:pcp-pmda-oracle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:pcp-pmda-pdns");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:pcp-pmda-perfevent");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:pcp-pmda-postfix");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:pcp-pmda-postgresql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:pcp-pmda-prometheus");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:pcp-pmda-redis");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:pcp-pmda-roomtemp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:pcp-pmda-rpm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:pcp-pmda-rsyslog");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:pcp-pmda-samba");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:pcp-pmda-sendmail");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:pcp-pmda-shping");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:pcp-pmda-slurm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:pcp-pmda-smart");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:pcp-pmda-snmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:pcp-pmda-summary");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:pcp-pmda-systemd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:pcp-pmda-trace");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:pcp-pmda-unbound");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:pcp-pmda-vmware");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:pcp-pmda-weblog");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:pcp-pmda-zimbra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:pcp-pmda-zswap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:pcp-selinux");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:pcp-system-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:pcp-testsuite");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:pcp-webapi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:pcp-webapp-blinkenlights");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:pcp-webapp-grafana");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:pcp-webapp-graphite");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:pcp-webapp-vector");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:pcp-webjs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:pcp-zeroconf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:perl-PCP-LogImport");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:perl-PCP-LogSummary");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:perl-PCP-MMV");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:perl-PCP-PMDA");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:python-pcp");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/03/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/10/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/10/21");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");
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


flag = 0;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"pcp-4.3.2-12.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"pcp-conf-4.3.2-12.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"pcp-debuginfo-4.3.2-12.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"pcp-devel-4.3.2-12.el7")) flag++;
if (rpm_check(release:"SL7", reference:"pcp-doc-4.3.2-12.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"pcp-doc-4.3.2-12.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"pcp-export-pcp2elasticsearch-4.3.2-12.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"pcp-export-pcp2graphite-4.3.2-12.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"pcp-export-pcp2influxdb-4.3.2-12.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"pcp-export-pcp2json-4.3.2-12.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"pcp-export-pcp2spark-4.3.2-12.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"pcp-export-pcp2xml-4.3.2-12.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"pcp-export-pcp2zabbix-4.3.2-12.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"pcp-export-zabbix-agent-4.3.2-12.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"pcp-gui-4.3.2-12.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"pcp-import-collectl2pcp-4.3.2-12.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"pcp-import-ganglia2pcp-4.3.2-12.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"pcp-import-iostat2pcp-4.3.2-12.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"pcp-import-mrtg2pcp-4.3.2-12.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"pcp-import-sar2pcp-4.3.2-12.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"pcp-libs-4.3.2-12.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"pcp-libs-devel-4.3.2-12.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"pcp-manager-4.3.2-12.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"pcp-pmda-activemq-4.3.2-12.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"pcp-pmda-apache-4.3.2-12.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"pcp-pmda-bash-4.3.2-12.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"pcp-pmda-bcc-4.3.2-12.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"pcp-pmda-bind2-4.3.2-12.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"pcp-pmda-bonding-4.3.2-12.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"pcp-pmda-cifs-4.3.2-12.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"pcp-pmda-cisco-4.3.2-12.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"pcp-pmda-dbping-4.3.2-12.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"pcp-pmda-dm-4.3.2-12.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"pcp-pmda-docker-4.3.2-12.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"pcp-pmda-ds389-4.3.2-12.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"pcp-pmda-ds389log-4.3.2-12.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"pcp-pmda-elasticsearch-4.3.2-12.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"pcp-pmda-gfs2-4.3.2-12.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"pcp-pmda-gluster-4.3.2-12.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"pcp-pmda-gpfs-4.3.2-12.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"pcp-pmda-gpsd-4.3.2-12.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"pcp-pmda-haproxy-4.3.2-12.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"pcp-pmda-infiniband-4.3.2-12.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"pcp-pmda-json-4.3.2-12.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"pcp-pmda-libvirt-4.3.2-12.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"pcp-pmda-lio-4.3.2-12.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"pcp-pmda-lmsensors-4.3.2-12.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"pcp-pmda-logger-4.3.2-12.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"pcp-pmda-lustre-4.3.2-12.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"pcp-pmda-lustrecomm-4.3.2-12.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"pcp-pmda-mailq-4.3.2-12.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"pcp-pmda-memcache-4.3.2-12.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"pcp-pmda-mic-4.3.2-12.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"pcp-pmda-mounts-4.3.2-12.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"pcp-pmda-mysql-4.3.2-12.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"pcp-pmda-named-4.3.2-12.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"pcp-pmda-netfilter-4.3.2-12.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"pcp-pmda-news-4.3.2-12.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"pcp-pmda-nfsclient-4.3.2-12.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"pcp-pmda-nginx-4.3.2-12.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"pcp-pmda-nvidia-gpu-4.3.2-12.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"pcp-pmda-oracle-4.3.2-12.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"pcp-pmda-pdns-4.3.2-12.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"pcp-pmda-perfevent-4.3.2-12.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"pcp-pmda-postfix-4.3.2-12.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"pcp-pmda-postgresql-4.3.2-12.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"pcp-pmda-prometheus-4.3.2-12.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"pcp-pmda-redis-4.3.2-12.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"pcp-pmda-roomtemp-4.3.2-12.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"pcp-pmda-rpm-4.3.2-12.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"pcp-pmda-rsyslog-4.3.2-12.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"pcp-pmda-samba-4.3.2-12.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"pcp-pmda-sendmail-4.3.2-12.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"pcp-pmda-shping-4.3.2-12.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"pcp-pmda-slurm-4.3.2-12.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"pcp-pmda-smart-4.3.2-12.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"pcp-pmda-snmp-4.3.2-12.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"pcp-pmda-summary-4.3.2-12.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"pcp-pmda-systemd-4.3.2-12.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"pcp-pmda-trace-4.3.2-12.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"pcp-pmda-unbound-4.3.2-12.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"pcp-pmda-vmware-4.3.2-12.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"pcp-pmda-weblog-4.3.2-12.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"pcp-pmda-zimbra-4.3.2-12.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"pcp-pmda-zswap-4.3.2-12.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"pcp-selinux-4.3.2-12.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"pcp-system-tools-4.3.2-12.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"pcp-testsuite-4.3.2-12.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"pcp-webapi-4.3.2-12.el7")) flag++;
if (rpm_check(release:"SL7", reference:"pcp-webapp-blinkenlights-4.3.2-12.el7")) flag++;
if (rpm_check(release:"SL7", reference:"pcp-webapp-grafana-4.3.2-12.el7")) flag++;
if (rpm_check(release:"SL7", reference:"pcp-webapp-graphite-4.3.2-12.el7")) flag++;
if (rpm_check(release:"SL7", reference:"pcp-webapp-vector-4.3.2-12.el7")) flag++;
if (rpm_check(release:"SL7", reference:"pcp-webjs-4.3.2-12.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"pcp-zeroconf-4.3.2-12.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"perl-PCP-LogImport-4.3.2-12.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"perl-PCP-LogSummary-4.3.2-12.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"perl-PCP-MMV-4.3.2-12.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"perl-PCP-PMDA-4.3.2-12.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"python-pcp-4.3.2-12.el7")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "pcp / pcp-conf / pcp-debuginfo / pcp-devel / pcp-doc / etc");
}
