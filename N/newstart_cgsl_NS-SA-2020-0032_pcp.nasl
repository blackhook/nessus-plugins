#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

# The descriptive text and package checks in this plugin were
# extracted from ZTE advisory NS-SA-2020-0032. The text
# itself is copyright (C) ZTE, Inc.

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(138771);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id(
    "CVE-2012-3418",
    "CVE-2012-3419",
    "CVE-2012-3420",
    "CVE-2012-3421",
    "CVE-2012-5530"
  );
  script_bugtraq_id(55041, 56656);

  script_name(english:"NewStart CGSL MAIN 6.01 : pcp Multiple Vulnerabilities (NS-SA-2020-0032)");

  script_set_attribute(attribute:"synopsis", value:
"The remote machine is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote NewStart CGSL host, running version MAIN 6.01, has pcp packages installed that are affected by multiple
vulnerabilities:

  - libpcp in Performance Co-Pilot (PCP) before 3.6.5 allows
    remote attackers to cause a denial of service and
    possibly execute arbitrary code via (1) a PDU with the
    numcreds field value greater than the number of actual
    elements to the __pmDecodeCreds function in p_creds.c;
    (2) the string byte number value to the
    __pmDecodeNameList function in p_pmns.c; (3) the numids
    value to the __pmDecodeIDList function in p_pmns.c; (4)
    unspecified vectors to the __pmDecodeProfile function in
    p_profile.c; the (5) status number value or (6) string
    number value to the __pmDecodeNameList function in
    p_pmns.c; (7) certain input to the __pmDecodeResult
    function in p_result.c; (8) the name length field
    (namelen) to the DecodeNameReq function in p_pmns.c; (9)
    a crafted PDU_FETCH request to the __pmDecodeFetch
    function in p_fetch.c; (10) the namelen field in the
    __pmDecodeInstanceReq function in p_instance.c; (11) the
    buflen field to the __pmDecodeText function in p_text.c;
    (12) PDU_INSTANCE packets to the __pmDecodeInstance in
    p_instance.c; or the (13) c_numpmid or (14) v_numval
    fields to the __pmDecodeLogControl function in
    p_lcontrol.c, which triggers integer overflows, heap-
    based buffer overflows, and/or buffer over-reads.
    (CVE-2012-3418)

  - Performance Co-Pilot (PCP) before 3.6.5 exports some of
    the /proc file system, which allows attackers to obtain
    sensitive information such as proc/pid/maps and command
    line arguments. (CVE-2012-3419)

  - Multiple memory leaks in Performance Co-Pilot (PCP)
    before 3.6.5 allow remote attackers to cause a denial of
    service (memory consumption or daemon crash) via a large
    number of PDUs with (1) a crafted context number to the
    DoFetch function in pmcd/src/dofetch.c or (2) a negative
    type value to the __pmGetPDU function in
    libpcp/src/pdu.c. (CVE-2012-3420)

  - The pduread function in pdu.c in libpcp in Performance
    Co-Pilot (PCP) before 3.6.5 does not properly time out
    connections, which allows remote attackers to cause a
    denial of service (pmcd hang) by sending individual
    bytes of a PDU separately, related to an event-driven
    programming flaw. (CVE-2012-3421)

  - The (1) pcmd and (2) pmlogger init scripts in
    Performance Co-Pilot (PCP) before 3.6.10 allow local
    users to overwrite arbitrary files via a symlink attack
    on a /var/tmp/##### temporary file. (CVE-2012-5530)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/notice/NS-SA-2020-0032");
  script_set_attribute(attribute:"solution", value:
"Upgrade the vulnerable CGSL pcp packages. Note that updated packages may not be available yet. Please contact ZTE for
more information.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2012-3419");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/08/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/07/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/07/21");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"NewStart CGSL Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2020-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/ZTE-CGSL/release", "Host/ZTE-CGSL/rpm-list", "Host/cpu");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

release = get_kb_item("Host/ZTE-CGSL/release");
if (isnull(release) || release !~ "^CGSL (MAIN|CORE)") audit(AUDIT_OS_NOT, "NewStart Carrier Grade Server Linux");

if (release !~ "CGSL MAIN 6.01")
  audit(AUDIT_OS_NOT, 'NewStart CGSL MAIN 6.01');

if (!get_kb_item("Host/ZTE-CGSL/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "NewStart Carrier Grade Server Linux", cpu);

flag = 0;

pkgs = {
  "CGSL MAIN 6.01": [
    "pcp-4.3.2-2.el8.cgslv6.0.2.g30e4cb1",
    "pcp-conf-4.3.2-2.el8.cgslv6.0.2.g30e4cb1",
    "pcp-debuginfo-4.3.2-2.el8.cgslv6.0.2.g30e4cb1",
    "pcp-debugsource-4.3.2-2.el8.cgslv6.0.2.g30e4cb1",
    "pcp-devel-4.3.2-2.el8.cgslv6.0.2.g30e4cb1",
    "pcp-devel-debuginfo-4.3.2-2.el8.cgslv6.0.2.g30e4cb1",
    "pcp-doc-4.3.2-2.el8.cgslv6.0.2.g30e4cb1",
    "pcp-export-pcp2elasticsearch-4.3.2-2.el8.cgslv6.0.2.g30e4cb1",
    "pcp-export-pcp2graphite-4.3.2-2.el8.cgslv6.0.2.g30e4cb1",
    "pcp-export-pcp2influxdb-4.3.2-2.el8.cgslv6.0.2.g30e4cb1",
    "pcp-export-pcp2json-4.3.2-2.el8.cgslv6.0.2.g30e4cb1",
    "pcp-export-pcp2spark-4.3.2-2.el8.cgslv6.0.2.g30e4cb1",
    "pcp-export-pcp2xml-4.3.2-2.el8.cgslv6.0.2.g30e4cb1",
    "pcp-export-pcp2zabbix-4.3.2-2.el8.cgslv6.0.2.g30e4cb1",
    "pcp-export-zabbix-agent-4.3.2-2.el8.cgslv6.0.2.g30e4cb1",
    "pcp-export-zabbix-agent-debuginfo-4.3.2-2.el8.cgslv6.0.2.g30e4cb1",
    "pcp-gui-4.3.2-2.el8.cgslv6.0.2.g30e4cb1",
    "pcp-gui-debuginfo-4.3.2-2.el8.cgslv6.0.2.g30e4cb1",
    "pcp-import-collectl2pcp-4.3.2-2.el8.cgslv6.0.2.g30e4cb1",
    "pcp-import-collectl2pcp-debuginfo-4.3.2-2.el8.cgslv6.0.2.g30e4cb1",
    "pcp-import-ganglia2pcp-4.3.2-2.el8.cgslv6.0.2.g30e4cb1",
    "pcp-import-iostat2pcp-4.3.2-2.el8.cgslv6.0.2.g30e4cb1",
    "pcp-import-mrtg2pcp-4.3.2-2.el8.cgslv6.0.2.g30e4cb1",
    "pcp-import-sar2pcp-4.3.2-2.el8.cgslv6.0.2.g30e4cb1",
    "pcp-libs-4.3.2-2.el8.cgslv6.0.2.g30e4cb1",
    "pcp-libs-debuginfo-4.3.2-2.el8.cgslv6.0.2.g30e4cb1",
    "pcp-libs-devel-4.3.2-2.el8.cgslv6.0.2.g30e4cb1",
    "pcp-manager-4.3.2-2.el8.cgslv6.0.2.g30e4cb1",
    "pcp-manager-debuginfo-4.3.2-2.el8.cgslv6.0.2.g30e4cb1",
    "pcp-pmda-activemq-4.3.2-2.el8.cgslv6.0.2.g30e4cb1",
    "pcp-pmda-apache-4.3.2-2.el8.cgslv6.0.2.g30e4cb1",
    "pcp-pmda-apache-debuginfo-4.3.2-2.el8.cgslv6.0.2.g30e4cb1",
    "pcp-pmda-bash-4.3.2-2.el8.cgslv6.0.2.g30e4cb1",
    "pcp-pmda-bash-debuginfo-4.3.2-2.el8.cgslv6.0.2.g30e4cb1",
    "pcp-pmda-bcc-4.3.2-2.el8.cgslv6.0.2.g30e4cb1",
    "pcp-pmda-bind2-4.3.2-2.el8.cgslv6.0.2.g30e4cb1",
    "pcp-pmda-bonding-4.3.2-2.el8.cgslv6.0.2.g30e4cb1",
    "pcp-pmda-cifs-4.3.2-2.el8.cgslv6.0.2.g30e4cb1",
    "pcp-pmda-cifs-debuginfo-4.3.2-2.el8.cgslv6.0.2.g30e4cb1",
    "pcp-pmda-cisco-4.3.2-2.el8.cgslv6.0.2.g30e4cb1",
    "pcp-pmda-cisco-debuginfo-4.3.2-2.el8.cgslv6.0.2.g30e4cb1",
    "pcp-pmda-dbping-4.3.2-2.el8.cgslv6.0.2.g30e4cb1",
    "pcp-pmda-dm-4.3.2-2.el8.cgslv6.0.2.g30e4cb1",
    "pcp-pmda-dm-debuginfo-4.3.2-2.el8.cgslv6.0.2.g30e4cb1",
    "pcp-pmda-docker-4.3.2-2.el8.cgslv6.0.2.g30e4cb1",
    "pcp-pmda-docker-debuginfo-4.3.2-2.el8.cgslv6.0.2.g30e4cb1",
    "pcp-pmda-ds389-4.3.2-2.el8.cgslv6.0.2.g30e4cb1",
    "pcp-pmda-ds389log-4.3.2-2.el8.cgslv6.0.2.g30e4cb1",
    "pcp-pmda-elasticsearch-4.3.2-2.el8.cgslv6.0.2.g30e4cb1",
    "pcp-pmda-gfs2-4.3.2-2.el8.cgslv6.0.2.g30e4cb1",
    "pcp-pmda-gfs2-debuginfo-4.3.2-2.el8.cgslv6.0.2.g30e4cb1",
    "pcp-pmda-gluster-4.3.2-2.el8.cgslv6.0.2.g30e4cb1",
    "pcp-pmda-gpfs-4.3.2-2.el8.cgslv6.0.2.g30e4cb1",
    "pcp-pmda-gpsd-4.3.2-2.el8.cgslv6.0.2.g30e4cb1",
    "pcp-pmda-haproxy-4.3.2-2.el8.cgslv6.0.2.g30e4cb1",
    "pcp-pmda-infiniband-4.3.2-2.el8.cgslv6.0.2.g30e4cb1",
    "pcp-pmda-infiniband-debuginfo-4.3.2-2.el8.cgslv6.0.2.g30e4cb1",
    "pcp-pmda-json-4.3.2-2.el8.cgslv6.0.2.g30e4cb1",
    "pcp-pmda-libvirt-4.3.2-2.el8.cgslv6.0.2.g30e4cb1",
    "pcp-pmda-lio-4.3.2-2.el8.cgslv6.0.2.g30e4cb1",
    "pcp-pmda-lmsensors-4.3.2-2.el8.cgslv6.0.2.g30e4cb1",
    "pcp-pmda-logger-4.3.2-2.el8.cgslv6.0.2.g30e4cb1",
    "pcp-pmda-logger-debuginfo-4.3.2-2.el8.cgslv6.0.2.g30e4cb1",
    "pcp-pmda-lustre-4.3.2-2.el8.cgslv6.0.2.g30e4cb1",
    "pcp-pmda-lustrecomm-4.3.2-2.el8.cgslv6.0.2.g30e4cb1",
    "pcp-pmda-lustrecomm-debuginfo-4.3.2-2.el8.cgslv6.0.2.g30e4cb1",
    "pcp-pmda-mailq-4.3.2-2.el8.cgslv6.0.2.g30e4cb1",
    "pcp-pmda-mailq-debuginfo-4.3.2-2.el8.cgslv6.0.2.g30e4cb1",
    "pcp-pmda-memcache-4.3.2-2.el8.cgslv6.0.2.g30e4cb1",
    "pcp-pmda-mic-4.3.2-2.el8.cgslv6.0.2.g30e4cb1",
    "pcp-pmda-mounts-4.3.2-2.el8.cgslv6.0.2.g30e4cb1",
    "pcp-pmda-mounts-debuginfo-4.3.2-2.el8.cgslv6.0.2.g30e4cb1",
    "pcp-pmda-mysql-4.3.2-2.el8.cgslv6.0.2.g30e4cb1",
    "pcp-pmda-named-4.3.2-2.el8.cgslv6.0.2.g30e4cb1",
    "pcp-pmda-netfilter-4.3.2-2.el8.cgslv6.0.2.g30e4cb1",
    "pcp-pmda-news-4.3.2-2.el8.cgslv6.0.2.g30e4cb1",
    "pcp-pmda-nfsclient-4.3.2-2.el8.cgslv6.0.2.g30e4cb1",
    "pcp-pmda-nginx-4.3.2-2.el8.cgslv6.0.2.g30e4cb1",
    "pcp-pmda-nvidia-gpu-4.3.2-2.el8.cgslv6.0.2.g30e4cb1",
    "pcp-pmda-nvidia-gpu-debuginfo-4.3.2-2.el8.cgslv6.0.2.g30e4cb1",
    "pcp-pmda-oracle-4.3.2-2.el8.cgslv6.0.2.g30e4cb1",
    "pcp-pmda-pdns-4.3.2-2.el8.cgslv6.0.2.g30e4cb1",
    "pcp-pmda-perfevent-4.3.2-2.el8.cgslv6.0.2.g30e4cb1",
    "pcp-pmda-perfevent-debuginfo-4.3.2-2.el8.cgslv6.0.2.g30e4cb1",
    "pcp-pmda-podman-4.3.2-2.el8.cgslv6.0.2.g30e4cb1",
    "pcp-pmda-podman-debuginfo-4.3.2-2.el8.cgslv6.0.2.g30e4cb1",
    "pcp-pmda-postfix-4.3.2-2.el8.cgslv6.0.2.g30e4cb1",
    "pcp-pmda-postgresql-4.3.2-2.el8.cgslv6.0.2.g30e4cb1",
    "pcp-pmda-prometheus-4.3.2-2.el8.cgslv6.0.2.g30e4cb1",
    "pcp-pmda-redis-4.3.2-2.el8.cgslv6.0.2.g30e4cb1",
    "pcp-pmda-roomtemp-4.3.2-2.el8.cgslv6.0.2.g30e4cb1",
    "pcp-pmda-roomtemp-debuginfo-4.3.2-2.el8.cgslv6.0.2.g30e4cb1",
    "pcp-pmda-rpm-4.3.2-2.el8.cgslv6.0.2.g30e4cb1",
    "pcp-pmda-rpm-debuginfo-4.3.2-2.el8.cgslv6.0.2.g30e4cb1",
    "pcp-pmda-rsyslog-4.3.2-2.el8.cgslv6.0.2.g30e4cb1",
    "pcp-pmda-samba-4.3.2-2.el8.cgslv6.0.2.g30e4cb1",
    "pcp-pmda-sendmail-4.3.2-2.el8.cgslv6.0.2.g30e4cb1",
    "pcp-pmda-sendmail-debuginfo-4.3.2-2.el8.cgslv6.0.2.g30e4cb1",
    "pcp-pmda-shping-4.3.2-2.el8.cgslv6.0.2.g30e4cb1",
    "pcp-pmda-shping-debuginfo-4.3.2-2.el8.cgslv6.0.2.g30e4cb1",
    "pcp-pmda-slurm-4.3.2-2.el8.cgslv6.0.2.g30e4cb1",
    "pcp-pmda-smart-4.3.2-2.el8.cgslv6.0.2.g30e4cb1",
    "pcp-pmda-smart-debuginfo-4.3.2-2.el8.cgslv6.0.2.g30e4cb1",
    "pcp-pmda-snmp-4.3.2-2.el8.cgslv6.0.2.g30e4cb1",
    "pcp-pmda-summary-4.3.2-2.el8.cgslv6.0.2.g30e4cb1",
    "pcp-pmda-summary-debuginfo-4.3.2-2.el8.cgslv6.0.2.g30e4cb1",
    "pcp-pmda-systemd-4.3.2-2.el8.cgslv6.0.2.g30e4cb1",
    "pcp-pmda-systemd-debuginfo-4.3.2-2.el8.cgslv6.0.2.g30e4cb1",
    "pcp-pmda-trace-4.3.2-2.el8.cgslv6.0.2.g30e4cb1",
    "pcp-pmda-trace-debuginfo-4.3.2-2.el8.cgslv6.0.2.g30e4cb1",
    "pcp-pmda-unbound-4.3.2-2.el8.cgslv6.0.2.g30e4cb1",
    "pcp-pmda-vmware-4.3.2-2.el8.cgslv6.0.2.g30e4cb1",
    "pcp-pmda-weblog-4.3.2-2.el8.cgslv6.0.2.g30e4cb1",
    "pcp-pmda-weblog-debuginfo-4.3.2-2.el8.cgslv6.0.2.g30e4cb1",
    "pcp-pmda-zimbra-4.3.2-2.el8.cgslv6.0.2.g30e4cb1",
    "pcp-pmda-zswap-4.3.2-2.el8.cgslv6.0.2.g30e4cb1",
    "pcp-selinux-4.3.2-2.el8.cgslv6.0.2.g30e4cb1",
    "pcp-system-tools-4.3.2-2.el8.cgslv6.0.2.g30e4cb1",
    "pcp-system-tools-debuginfo-4.3.2-2.el8.cgslv6.0.2.g30e4cb1",
    "pcp-testsuite-4.3.2-2.el8.cgslv6.0.2.g30e4cb1",
    "pcp-testsuite-debuginfo-4.3.2-2.el8.cgslv6.0.2.g30e4cb1",
    "pcp-webapi-4.3.2-2.el8.cgslv6.0.2.g30e4cb1",
    "pcp-webapi-debuginfo-4.3.2-2.el8.cgslv6.0.2.g30e4cb1",
    "pcp-webapp-blinkenlights-4.3.2-2.el8.cgslv6.0.2.g30e4cb1",
    "pcp-webapp-grafana-4.3.2-2.el8.cgslv6.0.2.g30e4cb1",
    "pcp-webapp-graphite-4.3.2-2.el8.cgslv6.0.2.g30e4cb1",
    "pcp-webapp-vector-4.3.2-2.el8.cgslv6.0.2.g30e4cb1",
    "pcp-webjs-4.3.2-2.el8.cgslv6.0.2.g30e4cb1",
    "pcp-zeroconf-4.3.2-2.el8.cgslv6.0.2.g30e4cb1",
    "perl-PCP-LogImport-4.3.2-2.el8.cgslv6.0.2.g30e4cb1",
    "perl-PCP-LogImport-debuginfo-4.3.2-2.el8.cgslv6.0.2.g30e4cb1",
    "perl-PCP-LogSummary-4.3.2-2.el8.cgslv6.0.2.g30e4cb1",
    "perl-PCP-MMV-4.3.2-2.el8.cgslv6.0.2.g30e4cb1",
    "perl-PCP-MMV-debuginfo-4.3.2-2.el8.cgslv6.0.2.g30e4cb1",
    "perl-PCP-PMDA-4.3.2-2.el8.cgslv6.0.2.g30e4cb1",
    "perl-PCP-PMDA-debuginfo-4.3.2-2.el8.cgslv6.0.2.g30e4cb1",
    "python3-pcp-4.3.2-2.el8.cgslv6.0.2.g30e4cb1",
    "python3-pcp-debuginfo-4.3.2-2.el8.cgslv6.0.2.g30e4cb1"
  ]
};
pkg_list = pkgs[release];

foreach (pkg in pkg_list)
  if (rpm_check(release:"ZTE " + release, reference:pkg)) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "pcp");
}
