#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-2616-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(148312);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/11");

  script_cve_id("CVE-2021-21341", "CVE-2021-21342", "CVE-2021-21343", "CVE-2021-21344", "CVE-2021-21345", "CVE-2021-21346", "CVE-2021-21347", "CVE-2021-21348", "CVE-2021-21349", "CVE-2021-21350", "CVE-2021-21351");

  script_name(english:"Debian DLA-2616-1 : libxstream-java security update");
  script_summary(english:"Checks dpkg output for the updated package.");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"In XStream there is a vulnerability which may allow a remote attacker
to load and execute arbitrary code from a remote host only by
manipulating the processed input stream.

The type hierarchies for java.io.InputStream,
java.nio.channels.Channel, javax.activation.DataSource and
javax.sql.rowsel.BaseRowSet are now blacklisted as well as the
individual types com.sun.corba.se.impl.activation.ServerTableEntry,
com.sun.tools.javac.processing.JavacProcessingEnvironment$NameProcessI
terator, sun.awt.datatransfer.DataTransferer$IndexOrderComparator, and
sun.swing.SwingLazyValue. Additionally the internal type
Accessor$GetterSetterReflection of JAXB, the internal types
MethodGetter$PrivilegedGetter and ServiceFinder$ServiceNameIterator of
JAX-WS, all inner classes of javafx.collections.ObservableList and an
internal ClassLoader used in a private BCEL copy are now part of the
default blacklist and the deserialization of XML containing one of the
types will fail. You will have to enable these types by explicit
configuration, if you need them.

For Debian 9 stretch, these problems have been fixed in version
1.4.11.1-1+deb9u2.

We recommend that you upgrade your libxstream-java packages.

For the detailed security status of libxstream-java please refer to
its security tracker page at:
https://security-tracker.debian.org/tracker/libxstream-java

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2021/04/msg00002.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/stretch/libxstream-java"
  );
  # https://security-tracker.debian.org/tracker/source-package/libxstream-java
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b2068716"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Upgrade the affected libxstream-java package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-21350");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libxstream-java");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:9.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/03/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/04/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/04/05");
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
if (deb_check(release:"9.0", prefix:"libxstream-java", reference:"1.4.11.1-1+deb9u2")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
