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

include("compat.inc");

if (description)
{
  script_id(119021);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/04/08");

  script_cve_id("CVE-2018-10851", "CVE-2018-14626", "CVE-2018-14644");

  script_name(english:"FreeBSD : powerdns-recursor -- Multiple vulnerabilities (e9aa0e4c-ea8b-11e8-a5b7-00e04c1ea73d)");
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
"powerdns Team reports :

CVE-2018-10851: An issue has been found in PowerDNS Recursor allowing
a malicious authoritative server to cause a memory leak by sending
specially crafted records. The issue is due to the fact that some
memory is allocated before the parsing and is not always properly
released if the record is malformed. When the PowerDNS Recursor is run
inside a supervisor like supervisord or systemd, an out-of-memory
crash will lead to an automatic restart, limiting the impact to a
somewhat degraded service.

CVE-2018-14626: An issue has been found in PowerDNS Recursor allowing
a remote user to craft a DNS query that will cause an answer without
DNSSEC records to be inserted into the packet cache and be returned to
clients asking for DNSSEC records, thus hiding the presence of DNSSEC
signatures for a specific qname and qtype. For a DNSSEC-signed domain,
this means that clients performing DNSSEC validation by themselves
might consider the answer to be bogus until it expires from the packet
cache, leading to a denial of service.

CVE-2018-14644: An issue has been found in PowerDNS Recursor where a
remote attacker sending a DNS query for a meta-type like OPT can lead
to a zone being wrongly cached as failing DNSSEC validation. It only
arises if the parent zone is signed, and all the authoritative servers
for that parent zone answer with FORMERR to a query for at least one
of the meta-types. As a result, subsequent queries from clients
requesting DNSSEC validation will be answered with a ServFail."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://doc.powerdns.com/recursor/changelog/4.1.html"
  );
  # https://vuxml.freebsd.org/freebsd/e9aa0e4c-ea8b-11e8-a5b7-00e04c1ea73d.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?e3064880"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:powerdns-recursor");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:powerdns-recursor40");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:freebsd:freebsd");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/11/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/11/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/11/19");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2018-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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

if (pkg_test(save_report:TRUE, pkg:"powerdns-recursor<4.1.7")) flag++;
if (pkg_test(save_report:TRUE, pkg:"powerdns-recursor40<4.0.9")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:pkg_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
