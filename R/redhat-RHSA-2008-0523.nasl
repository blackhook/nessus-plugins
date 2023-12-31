#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2008:0523. The text 
# itself is copyright (C) Red Hat, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(63857);
  script_version("1.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2004-0488", "CVE-2004-0700", "CVE-2004-0885", "CVE-2005-3352", "CVE-2006-1329", "CVE-2006-3918", "CVE-2006-5752", "CVE-2007-1349", "CVE-2007-3304", "CVE-2007-4465", "CVE-2007-5000", "CVE-2007-6388");
  script_xref(name:"RHSA", value:"2008:0523");

  script_name(english:"RHEL 3 / 4 : Proxy Server (RHSA-2008:0523)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Red Hat Network Proxy Server version 4.2.3 is now available. This
update includes fixes for a number of security issues in Red Hat
Network Proxy Server components.

This update has been rated as having low security impact by the Red
Hat Security Response Team.

The Red Hat Network Proxy Server 4.2.3 release corrects several
security vulnerabilities in several shipped components. In a typical
operating environment, these components are not exposed to users of
Proxy Server in a vulnerable manner. These security updates will
reduce risk in unique Proxy Server environments.

Multiple flaws were fixed in the Apache HTTPD server. These flaws
could result in a cross-site scripting or denial-of-service attack.
(CVE-2007-6388, CVE-2007-5000, CVE-2007-4465, CVE-2007-3304,
CVE-2006-5752, CVE-2006-3918, CVE-2005-3352)

A denial-of-service flaw was fixed in mod_perl. (CVE-2007-1349)

Multiple flaws in mod_ssl. (CVE-2004-0488, CVE-2004-0700,
CVE-2004-0885)

A denial-of-service flaw was fixed in the jabberd server.
(CVE-2006-1329)

Users of Red Hat Network Proxy Server 4.2 are advised to upgrade to
4.2.3, which resolves these issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2004-0488.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2004-0700.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2004-0885.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2005-3352.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2006-1329.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2006-3918.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2006-5752.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2007-1349.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2007-3304.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2007-4465.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2007-5000.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2007-6388.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2008-0523.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected jabberd, rhn-apache and / or rhn-modperl packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cwe_id(79, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jabberd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rhn-apache");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rhn-modperl");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:4");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/06/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/01/24");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2021 Tenable Network Security, Inc.");
  script_family(english:"Red Hat Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/RedHat/release", "Host/RedHat/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || "Red Hat" >!< release) audit(AUDIT_OS_NOT, "Red Hat");
if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

flag = 0;
if (rpm_check(release:"RHEL3", cpu:"i386", reference:"jabberd-2.0s10-3.37.rhn")) flag++;
if (rpm_check(release:"RHEL3", cpu:"i386", reference:"rhn-apache-1.3.27-36.rhn.rhel3")) flag++;
if (rpm_check(release:"RHEL3", cpu:"i386", reference:"rhn-modperl-1.29-16.rhel3")) flag++;

if (rpm_check(release:"RHEL4", cpu:"i386", reference:"jabberd-2.0s10-3.38.rhn")) flag++;
if (rpm_check(release:"RHEL4", cpu:"i386", reference:"rhn-apache-1.3.27-36.rhn.rhel4")) flag++;
if (rpm_check(release:"RHEL4", cpu:"i386", reference:"rhn-modperl-1.29-16.rhel4")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
