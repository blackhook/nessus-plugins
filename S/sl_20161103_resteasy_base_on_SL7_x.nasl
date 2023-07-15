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
  script_id(95859);
  script_version("3.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2016-7050");

  script_name(english:"Scientific Linux Security Update : resteasy-base on SL7.x (noarch) (20161103)");
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

  - It was discovered that under certain conditions RESTEasy
    could be forced to parse a request with
    SerializableProvider, resulting in deserialization of
    potentially untrusted data. An attacker could possibly
    use this flaw to execute arbitrary code with the
    permissions of the application using RESTEasy.
    (CVE-2016-7050)

Additional Changes :"
  );
  # https://listserv.fnal.gov/scripts/wa.exe?A2=ind1612&L=scientific-linux-errata&F=&S=&P=2024
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?fe27cbfb"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:resteasy-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:resteasy-base-atom-provider");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:resteasy-base-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:resteasy-base-jackson-provider");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:resteasy-base-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:resteasy-base-jaxb-provider");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:resteasy-base-jaxrs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:resteasy-base-jaxrs-all");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:resteasy-base-jaxrs-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:resteasy-base-jettison-provider");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:resteasy-base-providers-pom");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:resteasy-base-resteasy-pom");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:resteasy-base-tjws");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/06/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/11/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/12/15");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (rpm_check(release:"SL7", reference:"resteasy-base-3.0.6-4.el7")) flag++;
if (rpm_check(release:"SL7", reference:"resteasy-base-atom-provider-3.0.6-4.el7")) flag++;
if (rpm_check(release:"SL7", reference:"resteasy-base-client-3.0.6-4.el7")) flag++;
if (rpm_check(release:"SL7", reference:"resteasy-base-jackson-provider-3.0.6-4.el7")) flag++;
if (rpm_check(release:"SL7", reference:"resteasy-base-javadoc-3.0.6-4.el7")) flag++;
if (rpm_check(release:"SL7", reference:"resteasy-base-jaxb-provider-3.0.6-4.el7")) flag++;
if (rpm_check(release:"SL7", reference:"resteasy-base-jaxrs-3.0.6-4.el7")) flag++;
if (rpm_check(release:"SL7", reference:"resteasy-base-jaxrs-all-3.0.6-4.el7")) flag++;
if (rpm_check(release:"SL7", reference:"resteasy-base-jaxrs-api-3.0.6-4.el7")) flag++;
if (rpm_check(release:"SL7", reference:"resteasy-base-jettison-provider-3.0.6-4.el7")) flag++;
if (rpm_check(release:"SL7", reference:"resteasy-base-providers-pom-3.0.6-4.el7")) flag++;
if (rpm_check(release:"SL7", reference:"resteasy-base-resteasy-pom-3.0.6-4.el7")) flag++;
if (rpm_check(release:"SL7", reference:"resteasy-base-tjws-3.0.6-4.el7")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "resteasy-base / resteasy-base-atom-provider / resteasy-base-client / etc");
}
