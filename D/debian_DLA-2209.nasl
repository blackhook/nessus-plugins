#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-2209-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(136951);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/05");

  script_cve_id(
    "CVE-2019-17563",
    "CVE-2020-1935",
    "CVE-2020-1938",
    "CVE-2020-9484"
  );
  script_xref(name:"IAVA", value:"2020-A-0225-S");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/03/17");
  script_xref(name:"CEA-ID", value:"CEA-2021-0004");
  script_xref(name:"CEA-ID", value:"CEA-2020-0021");

  script_name(english:"Debian DLA-2209-1 : tomcat8 security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"Several security vulnerabilities have been discovered in the Tomcat
servlet and JSP engine.

WARNING: The fix for CVE-2020-1938 may disrupt services that rely on a
working AJP configuration. The option secretRequired defaults to true
now. You should define a secret in your server.xml or you can revert
back by setting secretRequired to false.

CVE-2019-17563

When using FORM authentication with Apache Tomcat there was a narrow
window where an attacker could perform a session fixation attack. The
window was considered too narrow for an exploit to be practical but,
erring on the side of caution, this issue has been treated as a
security vulnerability.

CVE-2020-1935

In Apache Tomcat the HTTP header parsing code used an approach to
end-of-line parsing that allowed some invalid HTTP headers to be
parsed as valid. This led to a possibility of HTTP Request Smuggling
if Tomcat was located behind a reverse proxy that incorrectly handled
the invalid Transfer-Encoding header in a particular manner. Such a
reverse proxy is considered unlikely.

CVE-2020-1938

When using the Apache JServ Protocol (AJP), care must be taken when
trusting incoming connections to Apache Tomcat. Tomcat treats AJP
connections as having higher trust than, for example, a similar HTTP
connection. If such connections are available to an attacker, they can
be exploited in ways that may be surprising. Previously Tomcat shipped
with an AJP Connector enabled by default that listened on all
configured IP addresses. It was expected (and recommended in the
security guide) that this Connector would be disabled if not required.
. Note that Debian already disabled the AJP connector by default.
Mitigation is only required if the AJP port was made accessible to
untrusted users.

CVE-2020-9484

When using Apache Tomcat and an attacker is able to control the
contents and name of a file on the server; and b) the server is
configured to use the PersistenceManager with a FileStore; and c) the
PersistenceManager is configured with
sessionAttributeValueClassNameFilter='null' (the default unless a
SecurityManager is used) or a sufficiently lax filter to allow the
attacker provided object to be deserialized; and d) the attacker knows
the relative file path from the storage location used by FileStore to
the file the attacker has control over; then, using a specifically
crafted request, the attacker will be able to trigger remote code
execution via deserialization of the file under their control. Note
that all of conditions a) to d) must be true for the attack to
succeed.

For Debian 8 'Jessie', these problems have been fixed in version
8.0.14-1+deb8u17.

We recommend that you upgrade your tomcat8 packages.

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues.");
  script_set_attribute(attribute:"see_also", value:"https://lists.debian.org/debian-lts-announce/2020/05/msg00026.html");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/jessie/tomcat8");
  script_set_attribute(attribute:"solution", value:
"Upgrade the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/12/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/05/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/05/29");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libservlet3.1-java");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libservlet3.1-java-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libtomcat8-java");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:tomcat8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:tomcat8-admin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:tomcat8-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:tomcat8-docs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:tomcat8-examples");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:tomcat8-user");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:8.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Debian Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2020-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/Debian/release", "Host/Debian/dpkg-l");

  exit(0);
}


include("audit.inc");
include("debian_package.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/Debian/release")) audit(AUDIT_OS_NOT, "Debian");
if (!get_kb_item("Host/Debian/dpkg-l")) audit(AUDIT_PACKAGE_LIST_MISSING);


flag = 0;
if (deb_check(release:"8.0", prefix:"libservlet3.1-java", reference:"8.0.14-1+deb8u17")) flag++;
if (deb_check(release:"8.0", prefix:"libservlet3.1-java-doc", reference:"8.0.14-1+deb8u17")) flag++;
if (deb_check(release:"8.0", prefix:"libtomcat8-java", reference:"8.0.14-1+deb8u17")) flag++;
if (deb_check(release:"8.0", prefix:"tomcat8", reference:"8.0.14-1+deb8u17")) flag++;
if (deb_check(release:"8.0", prefix:"tomcat8-admin", reference:"8.0.14-1+deb8u17")) flag++;
if (deb_check(release:"8.0", prefix:"tomcat8-common", reference:"8.0.14-1+deb8u17")) flag++;
if (deb_check(release:"8.0", prefix:"tomcat8-docs", reference:"8.0.14-1+deb8u17")) flag++;
if (deb_check(release:"8.0", prefix:"tomcat8-examples", reference:"8.0.14-1+deb8u17")) flag++;
if (deb_check(release:"8.0", prefix:"tomcat8-user", reference:"8.0.14-1+deb8u17")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
