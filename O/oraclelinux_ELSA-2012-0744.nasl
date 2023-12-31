#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2012:0744 and 
# Oracle Linux Security Advisory ELSA-2012-0744 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(68545);
  script_version("1.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2011-4940", "CVE-2011-4944", "CVE-2012-0845", "CVE-2012-1150");
  script_bugtraq_id(51239, 51996, 52379, 52732);
  script_xref(name:"RHSA", value:"2012:0744");

  script_name(english:"Oracle Linux 6 : python (ELSA-2012-0744)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Oracle Linux host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"From Red Hat Security Advisory 2012:0744 :

Updated python packages that fix multiple security issues are now
available for Red Hat Enterprise Linux 6.

The Red Hat Security Response Team has rated this update as having
moderate security impact. Common Vulnerability Scoring System (CVSS)
base scores, which give detailed severity ratings, are available for
each vulnerability from the CVE links in the References section.

Python is an interpreted, interactive, object-oriented programming
language.

A denial of service flaw was found in the implementation of
associative arrays (dictionaries) in Python. An attacker able to
supply a large number of inputs to a Python application (such as HTTP
POST request parameters sent to a web application) that are used as
keys when inserting data into an array could trigger multiple hash
function collisions, making array operations take an excessive amount
of CPU time. To mitigate this issue, randomization has been added to
the hash function to reduce the chance of an attacker successfully
causing intentional collisions. (CVE-2012-1150)

Note: The hash randomization is not enabled by default as it may break
applications that incorrectly depend on dictionary ordering. To enable
the protection, the new 'PYTHONHASHSEED' environment variable or the
Python interpreter's '-R' command line option can be used. Refer to
the python(1) manual page for details.

The RHSA-2012:0731 expat erratum must be installed with this update,
which adds hash randomization to the Expat library used by the Python
pyexpat module.

A flaw was found in the way the Python SimpleXMLRPCServer module
handled clients disconnecting prematurely. A remote attacker could use
this flaw to cause excessive CPU consumption on a server using
SimpleXMLRPCServer. (CVE-2012-0845)

A flaw was found in the way the Python SimpleHTTPServer module
generated directory listings. An attacker able to upload a file with a
specially crafted name to a server could possibly perform a cross-site
scripting (XSS) attack against victims visiting a listing page
generated by SimpleHTTPServer, for a directory containing the crafted
file (if the victims were using certain web browsers). (CVE-2011-4940)

A race condition was found in the way the Python distutils module set
file permissions during the creation of the .pypirc file. If a local
user had access to the home directory of another user who is running
distutils, they could use this flaw to gain access to that user's
.pypirc file, which can contain usernames and passwords for code
repositories. (CVE-2011-4944)

Red Hat would like to thank oCERT for reporting CVE-2012-1150. oCERT
acknowledges Julian Walde and Alexander Klink as the original
reporters of CVE-2012-1150.

All Python users should upgrade to these updated packages, which
contain backported patches to correct these issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2012-June/002866.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected python packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python-test");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:tkinter");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:6");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/06/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/06/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/07/12");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"Oracle Linux Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/OracleLinux", "Host/RedHat/release", "Host/RedHat/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/OracleLinux")) audit(AUDIT_OS_NOT, "Oracle Linux");
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || !pregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux)", string:release)) audit(AUDIT_OS_NOT, "Oracle Linux");
os_ver = pregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux) .*release ([0-9]+(\.[0-9]+)?)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Oracle Linux");
os_ver = os_ver[1];
if (! preg(pattern:"^6([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Oracle Linux 6", "Oracle Linux " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Oracle Linux", cpu);

flag = 0;
if (rpm_check(release:"EL6", reference:"python-2.6.6-29.el6_2.2")) flag++;
if (rpm_check(release:"EL6", reference:"python-devel-2.6.6-29.el6_2.2")) flag++;
if (rpm_check(release:"EL6", reference:"python-libs-2.6.6-29.el6_2.2")) flag++;
if (rpm_check(release:"EL6", reference:"python-test-2.6.6-29.el6_2.2")) flag++;
if (rpm_check(release:"EL6", reference:"python-tools-2.6.6-29.el6_2.2")) flag++;
if (rpm_check(release:"EL6", reference:"tkinter-2.6.6-29.el6_2.2")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "python / python-devel / python-libs / python-test / python-tools / etc");
}
