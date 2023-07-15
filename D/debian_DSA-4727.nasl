#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-4727. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(138647);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/06");

  script_cve_id("CVE-2020-11996", "CVE-2020-13934", "CVE-2020-13935", "CVE-2020-9484");
  script_xref(name:"DSA", value:"4727");
  script_xref(name:"IAVA", value:"2020-A-0316-S");
  script_xref(name:"CEA-ID", value:"CEA-2021-0004");

  script_name(english:"Debian DSA-4727-1 : tomcat9 - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"Several vulnerabilities were discovered in the Tomcat servlet and JSP
engine, which could result in code execution or denial of service."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/source-package/tomcat9"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/buster/tomcat9"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.debian.org/security/2020/dsa-4727"
  );
  script_set_attribute(
    attribute:"solution",
    value:
"Upgrade the tomcat9 packages.

For the stable distribution (buster), these problems have been fixed
in version 9.0.31-1~deb10u2."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-9484");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:tomcat9");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:10.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/05/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/07/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/07/20");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2020-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (deb_check(release:"10.0", prefix:"libtomcat9-embed-java", reference:"9.0.31-1~deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"libtomcat9-java", reference:"9.0.31-1~deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"tomcat9", reference:"9.0.31-1~deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"tomcat9-admin", reference:"9.0.31-1~deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"tomcat9-common", reference:"9.0.31-1~deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"tomcat9-docs", reference:"9.0.31-1~deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"tomcat9-examples", reference:"9.0.31-1~deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"tomcat9-user", reference:"9.0.31-1~deb10u2")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
