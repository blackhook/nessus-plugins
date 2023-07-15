#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-2635-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(149004);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/06");

  script_cve_id("CVE-2018-11039", "CVE-2018-11040", "CVE-2018-1270", "CVE-2018-15756");
  script_xref(name:"CEA-ID", value:"CEA-2021-0004");

  script_name(english:"Debian DLA-2635-1 : libspring-java security update");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"Multiple vulnerabilities were discovered in libspring-java, a modular
Java/J2EE application framework. An attacker may execute code, perform
XST attack, issue unauthorized cross-domain requests or cause a DoS
(denial of service) in specific configurations.

CVE-2018-1270

Spring Framework allows applications to expose STOMP over WebSocket
endpoints with a simple, in-memory STOMP broker through the
spring-messaging module. A malicious user (or attacker) can craft a
message to the broker that can lead to a remote code execution attack.

CVE-2018-11039

Spring Framework allows web applications to change the HTTP request
method to any HTTP method (including TRACE) using the
HiddenHttpMethodFilter in Spring MVC. If an application has a
pre-existing XSS vulnerability, a malicious user (or attacker) can use
this filter to escalate to an XST (Cross Site Tracing) attack.

CVE-2018-11040

Spring Framework allows web applications to enable cross-domain
requests via JSONP (JSON with Padding) through
AbstractJsonpResponseBodyAdvice for REST controllers and
MappingJackson2JsonView for browser requests. Both are not enabled by
default in Spring Framework nor Spring Boot, however, when
MappingJackson2JsonView is configured in an application, JSONP support
is automatically ready to use through the 'jsonp' and 'callback' JSONP
parameters, enabling cross-domain requests.

CVE-2018-15756

Spring Framework provides support for range requests when serving
static resources through the ResourceHttpRequestHandler, or starting
in 5.0 when an annotated controller returns an
org.springframework.core.io.Resource. A malicious user (or attacker)
can add a range header with a high number of ranges, or with wide
ranges that overlap, or both, for a denial of service attack.

For Debian 9 stretch, these problems have been fixed in version
4.3.5-1+deb9u1.

We recommend that you upgrade your libspring-java packages.

For the detailed security status of libspring-java please refer to its
security tracker page at:
https://security-tracker.debian.org/tracker/libspring-java

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2021/04/msg00022.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/stretch/libspring-java"
  );
  # https://security-tracker.debian.org/tracker/source-package/libspring-java
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?6bb4a348"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libspring-aop-java");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libspring-beans-java");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libspring-context-java");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libspring-context-support-java");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libspring-core-java");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libspring-expression-java");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libspring-instrument-java");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libspring-jdbc-java");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libspring-jms-java");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libspring-messaging-java");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libspring-orm-java");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libspring-oxm-java");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libspring-test-java");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libspring-transaction-java");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libspring-web-java");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libspring-web-portlet-java");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libspring-web-servlet-java");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:9.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/04/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/04/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/04/27");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2021-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"Debian Local Security Checks");

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
if (deb_check(release:"9.0", prefix:"libspring-aop-java", reference:"4.3.5-1+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libspring-beans-java", reference:"4.3.5-1+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libspring-context-java", reference:"4.3.5-1+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libspring-context-support-java", reference:"4.3.5-1+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libspring-core-java", reference:"4.3.5-1+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libspring-expression-java", reference:"4.3.5-1+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libspring-instrument-java", reference:"4.3.5-1+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libspring-jdbc-java", reference:"4.3.5-1+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libspring-jms-java", reference:"4.3.5-1+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libspring-messaging-java", reference:"4.3.5-1+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libspring-orm-java", reference:"4.3.5-1+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libspring-oxm-java", reference:"4.3.5-1+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libspring-test-java", reference:"4.3.5-1+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libspring-transaction-java", reference:"4.3.5-1+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libspring-web-java", reference:"4.3.5-1+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libspring-web-portlet-java", reference:"4.3.5-1+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libspring-web-servlet-java", reference:"4.3.5-1+deb9u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
