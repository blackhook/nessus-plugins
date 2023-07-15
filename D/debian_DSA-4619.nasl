#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-4619. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(133534);
  script_version("1.2");
  script_cvs_date("Date: 2020/02/13");

  script_cve_id("CVE-2019-17570");
  script_xref(name:"DSA", value:"4619");

  script_name(english:"Debian DSA-4619-1 : libxmlrpc3-java - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Guillaume Teissier reported that the XMLRPC client in libxmlrpc3-java,
an XML-RPC implementation in Java, does perform deserialization of the
server-side exception serialized in the faultCause attribute of XMLRPC
error response messages. A malicious XMLRPC server can take advantage
of this flaw to execute arbitrary code with the privileges of an
application using the Apache XMLRPC client library.

Note that a client that expects to get server-side exceptions need to
set explicitly the enabledForExceptions property."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=949089"
  );
  # https://security-tracker.debian.org/tracker/source-package/libxmlrpc3-java
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?5fb81123"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/stretch/libxmlrpc3-java"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/buster/libxmlrpc3-java"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.debian.org/security/2020/dsa-4619"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the libxmlrpc3-java packages.

For the oldstable distribution (stretch), this problem has been fixed
in version 3.1.3-8+deb9u1.

For the stable distribution (buster), this problem has been fixed in
version 3.1.3-9+deb10u1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libxmlrpc3-java");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:10.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:9.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/01/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/02/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/02/07");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (deb_check(release:"10.0", prefix:"libxmlrpc3-client-java", reference:"3.1.3-9+deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"libxmlrpc3-common-java", reference:"3.1.3-9+deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"libxmlrpc3-java-doc", reference:"3.1.3-9+deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"libxmlrpc3-server-java", reference:"3.1.3-9+deb10u1")) flag++;
if (deb_check(release:"9.0", prefix:"libxmlrpc3-client-java", reference:"3.1.3-8+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libxmlrpc3-common-java", reference:"3.1.3-8+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libxmlrpc3-java-doc", reference:"3.1.3-8+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libxmlrpc3-server-java", reference:"3.1.3-8+deb9u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
