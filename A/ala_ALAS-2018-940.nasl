#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux AMI Security Advisory ALAS-2018-940.
#

include("compat.inc");

if (description)
{
  script_id(105620);
  script_version("3.3");
  script_cvs_date("Date: 2018/04/18 15:09:36");

  script_cve_id("CVE-2017-16820");
  script_xref(name:"ALAS", value:"2018-940");

  script_name(english:"Amazon Linux AMI : collectd (ALAS-2018-940)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Amazon Linux AMI host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Double free in csnmp_read_table function in snmp.c :

The csnmp_read_table function in snmp.c in the SNMP plugin in collectd
before 5.6.3 is susceptible to a double free in a certain error case,
which could lead to a crash (or potentially have other impact).
(CVE-2017-16820)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://alas.aws.amazon.com/ALAS-2018-940.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Run 'yum update collectd' to update your system."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:collectd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:collectd-amqp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:collectd-apache");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:collectd-bind");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:collectd-chrony");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:collectd-curl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:collectd-curl_xml");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:collectd-dbi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:collectd-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:collectd-disk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:collectd-dns");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:collectd-drbd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:collectd-email");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:collectd-generic-jmx");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:collectd-gmond");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:collectd-hugepages");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:collectd-ipmi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:collectd-iptables");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:collectd-ipvs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:collectd-java");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:collectd-lua");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:collectd-lvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:collectd-mcelog");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:collectd-memcachec");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:collectd-mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:collectd-netlink");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:collectd-nginx");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:collectd-notify_email");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:collectd-openldap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:collectd-postgresql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:collectd-python");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:collectd-rrdcached");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:collectd-rrdtool");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:collectd-snmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:collectd-snmp_agent");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:collectd-synproxy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:collectd-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:collectd-varnish");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:collectd-web");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:collectd-write_http");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:collectd-write_sensu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:collectd-write_tsdb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:collectd-zookeeper");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libcollectdclient");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libcollectdclient-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:perl-Collectd");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2018/01/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/01/08");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2018 Tenable Network Security, Inc.");
  script_family(english:"Amazon Linux Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/AmazonLinux/release", "Host/AmazonLinux/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

release = get_kb_item("Host/AmazonLinux/release");
if (isnull(release) || !strlen(release)) audit(AUDIT_OS_NOT, "Amazon Linux");
os_ver = pregmatch(pattern: "^AL(A|\d)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Amazon Linux");
os_ver = os_ver[1];
if (os_ver != "A")
{
  if (os_ver == 'A') os_ver = 'AMI';
  audit(AUDIT_OS_NOT, "Amazon Linux AMI", "Amazon Linux " + os_ver);
}

if (!get_kb_item("Host/AmazonLinux/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


flag = 0;
if (rpm_check(release:"ALA", reference:"collectd-5.8.0-2.19.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"collectd-amqp-5.8.0-2.19.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"collectd-apache-5.8.0-2.19.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"collectd-bind-5.8.0-2.19.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"collectd-chrony-5.8.0-2.19.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"collectd-curl-5.8.0-2.19.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"collectd-curl_xml-5.8.0-2.19.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"collectd-dbi-5.8.0-2.19.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"collectd-debuginfo-5.8.0-2.19.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"collectd-disk-5.8.0-2.19.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"collectd-dns-5.8.0-2.19.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"collectd-drbd-5.8.0-2.19.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"collectd-email-5.8.0-2.19.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"collectd-generic-jmx-5.8.0-2.19.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"collectd-gmond-5.8.0-2.19.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"collectd-hugepages-5.8.0-2.19.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"collectd-ipmi-5.8.0-2.19.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"collectd-iptables-5.8.0-2.19.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"collectd-ipvs-5.8.0-2.19.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"collectd-java-5.8.0-2.19.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"collectd-lua-5.8.0-2.19.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"collectd-lvm-5.8.0-2.19.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"collectd-mcelog-5.8.0-2.19.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"collectd-memcachec-5.8.0-2.19.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"collectd-mysql-5.8.0-2.19.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"collectd-netlink-5.8.0-2.19.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"collectd-nginx-5.8.0-2.19.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"collectd-notify_email-5.8.0-2.19.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"collectd-openldap-5.8.0-2.19.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"collectd-postgresql-5.8.0-2.19.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"collectd-python-5.8.0-2.19.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"collectd-rrdcached-5.8.0-2.19.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"collectd-rrdtool-5.8.0-2.19.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"collectd-snmp-5.8.0-2.19.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"collectd-snmp_agent-5.8.0-2.19.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"collectd-synproxy-5.8.0-2.19.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"collectd-utils-5.8.0-2.19.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"collectd-varnish-5.8.0-2.19.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"collectd-web-5.8.0-2.19.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"collectd-write_http-5.8.0-2.19.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"collectd-write_sensu-5.8.0-2.19.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"collectd-write_tsdb-5.8.0-2.19.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"collectd-zookeeper-5.8.0-2.19.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"libcollectdclient-5.8.0-2.19.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"libcollectdclient-devel-5.8.0-2.19.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"perl-Collectd-5.8.0-2.19.amzn1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "collectd / collectd-amqp / collectd-apache / collectd-bind / etc");
}
