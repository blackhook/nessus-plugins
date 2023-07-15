#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-2207. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(53212);
  script_version("1.18");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2008-5515", "CVE-2009-0033", "CVE-2009-0580", "CVE-2009-0781", "CVE-2009-0783", "CVE-2009-2693", "CVE-2009-2902", "CVE-2010-1157", "CVE-2010-2227");
  script_bugtraq_id(35193, 35196, 35263, 35416, 37944, 37945, 39635, 41544);
  script_xref(name:"DSA", value:"2207");

  script_name(english:"Debian DSA-2207-1 : tomcat5.5 - several vulnerabilities");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Various vulnerabilities have been discovered in the Tomcat Servlet and
JSP engine, resulting in denial of service, cross-site scripting,
information disclosure and WAR file traversal. Further details on the
individual security issues can be found on the Apache Tomcat 5
vulnerabilities page."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://tomcat.apache.org/security-5.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.debian.org/security/2011/dsa-2207"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the tomcat5.5 packages.

For the oldstable distribution (lenny), this problem has been fixed in
version 5.5.26-5lenny2.

The stable distribution (squeeze) no longer contains tomcat5.5.
tomcat6 is already fixed."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:H/UI:N/S:U/C:L/I:L/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'D2ExploitPack');
  script_cwe_id(20, 22, 79, 200);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:tomcat5.5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:5.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2009/03/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/03/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/03/30");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2011-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (deb_check(release:"5.0", prefix:"tomcat5.5", reference:"5.5.26-5lenny2")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
