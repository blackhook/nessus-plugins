#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from the FreeBSD VuXML database :
#
# Copyright 2003-2021 Jacques Vidrine and contributors
#
# Redistribution and use in source (VuXML) and 'compiled' forms (SGML,
# HTML, PDF, PostScript, RTF and so forth) with or without modification,
# are permitted provided that the following conditions are met:
# 1. Redistributions of source code (VuXML) must retain the above
#    copyright notice, this list of conditions and the following
#    disclaimer as the first lines of this file unmodified.
# 2. Redistributions in compiled form (transformed to other DTDs,
#    published online in any format, converted to PDF, PostScript,
#    RTF and other formats) must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer
#    in the documentation and/or other materials provided with the
#    distribution.
# 
# THIS DOCUMENTATION IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
# THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
# PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS
# BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY,
# OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT
# OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
# BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
# WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE
# OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS DOCUMENTATION,
# EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#

include('deprecated_nasl_level.inc');
include("compat.inc");

if (description)
{
  script_id(153892);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/10/15");

  script_cve_id("CVE-2021-32626", "CVE-2021-32627", "CVE-2021-32628", "CVE-2021-32672", "CVE-2021-32675", "CVE-2021-32687", "CVE-2021-32762", "CVE-2021-41099");

  script_name(english:"FreeBSD : redis -- multiple vulnerabilities (9b4806c1-257f-11ec-9db5-0800270512f4)");
  script_summary(english:"Checks for updated packages in pkg_info output");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote FreeBSD host is missing one or more security-related
updates."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The Redis Team reports : CVE-2021-41099 Integer to heap buffer
overflow handling certain string commands and network payloads, when
proto-max-bulk-len is manually configured. CVE-2021-32762 Integer to
heap buffer overflow issue in redis-cli and redis-sentinel parsing
large multi-bulk replies on some older and less common platforms.
CVE-2021-32687 Integer to heap buffer overflow with intsets, when
set-max-intset-entries is manually configured to a non-default, very
large value. CVE-2021-32675 Denial Of Service when processing RESP
request payloads with a large number of elements on many connections.
CVE-2021-32672 Random heap reading issue with Lua Debugger.
CVE-2021-32628 Integer to heap buffer overflow handling
ziplist-encoded data types, when configuring a large, non-default
value for hash-max-ziplist-entries, hash-max-ziplist-value,
zset-max-ziplist-entries or zset-max-ziplist-value. CVE-2021-32627
Integer to heap buffer overflow issue with streams, when configuring a
non-default, large value for proto-max-bulk-len and
client-query-buffer-limit. CVE-2021-32626 Specially crafted Lua
scripts may result with Heap buffer overflow."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://groups.google.com/g/redis-db/c/GS_9L2KCk9g"
  );
  # https://vuxml.freebsd.org/freebsd/9b4806c1-257f-11ec-9db5-0800270512f4.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?8ecac2fb"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-32762");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:redis");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:redis-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:redis5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:redis6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:freebsd:freebsd");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/10/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/10/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/10/06");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"FreeBSD Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/FreeBSD/release", "Host/FreeBSD/pkg_info");

  exit(0);
}


include("audit.inc");
include("freebsd_package.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/FreeBSD/release")) audit(AUDIT_OS_NOT, "FreeBSD");
if (!get_kb_item("Host/FreeBSD/pkg_info")) audit(AUDIT_PACKAGE_LIST_MISSING);


flag = 0;

if (pkg_test(save_report:TRUE, pkg:"redis-devel<7.0.0.20211005")) flag++;
if (pkg_test(save_report:TRUE, pkg:"redis<6.2.6")) flag++;
if (pkg_test(save_report:TRUE, pkg:"redis6<6.0.16")) flag++;
if (pkg_test(save_report:TRUE, pkg:"redis5<5.0.14")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:pkg_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
