#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-4596. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(132427);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/02/23");

  script_cve_id("CVE-2018-11784", "CVE-2018-8014", "CVE-2019-0199", "CVE-2019-0221", "CVE-2019-12418", "CVE-2019-17563");
  script_xref(name:"DSA", value:"4596");
  script_xref(name:"CEA-ID", value:"CEA-2021-0004");
  script_xref(name:"CEA-ID", value:"CEA-2021-0025");

  script_name(english:"Debian DSA-4596-1 : tomcat8 - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"Several issues were discovered in the Tomcat servlet and JSP engine,
which could result in session fixation attacks, information
disclosure, cross-site scripting, denial of service via resource
exhaustion and insecure redirects."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/source-package/tomcat8"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/stretch/tomcat8"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.debian.org/security/2019/dsa-4596"
  );
  script_set_attribute(
    attribute:"solution",
    value:
"Upgrade the tomcat8 packages.

For the oldstable distribution (stretch), these problems have been
fixed in version 8.5.50-0+deb9u1. This update also requires an updated
version of tomcat-native which has been updated to 1.2.21-1~deb9u1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-8014");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:tomcat8");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:9.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/05/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/12/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/12/30");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2019-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (deb_check(release:"9.0", prefix:"libservlet3.1-java", reference:"8.5.50-0+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libservlet3.1-java-doc", reference:"8.5.50-0+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libtomcat8-embed-java", reference:"8.5.50-0+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libtomcat8-java", reference:"8.5.50-0+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"tomcat8", reference:"8.5.50-0+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"tomcat8-admin", reference:"8.5.50-0+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"tomcat8-common", reference:"8.5.50-0+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"tomcat8-docs", reference:"8.5.50-0+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"tomcat8-examples", reference:"8.5.50-0+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"tomcat8-user", reference:"8.5.50-0+deb9u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
