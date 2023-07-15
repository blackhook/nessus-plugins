##
# (C) Tenable Network Security, Inc.
##

include("compat.inc");

if (description)
{
  script_id(106716);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/03/11");

  script_name(english:"Microsoft Windows SMB2 and SMB3 Dialects Supported (remote check)");
  script_summary(english:"Checks which dialects of SMB2 and SMB3 are enabled on the remote host.");

  script_set_attribute(attribute:"synopsis", value:
"It was possible to obtain information about the dialects of SMB2 and SMB3 available
on the remote host.");
  script_set_attribute(attribute:"description", value:
"Nessus was able to obtain the set of SMB2 and SMB3 dialects running on the remote
host by sending an authentication request to port 139 or 445.");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2018/02/09");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"asset_inventory", value:"True");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2004-2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_require_ports(139,445);
  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("smb_func.inc");
include("agent.inc");
include("spad_log_func.inc");

function smb_compression_algorithm(comp_capa)
{
  local_var dlen, cnt, comp_name, supported, pos, i, id;

  supported = make_list();

  if(!isnull(comp_capa) && (dlen = strlen(comp_capa)) >= 10)
  {
    cnt = get_word(blob:ret[21], pos:0);
  
    comp_name[0] = 'NONE';
    comp_name[1] = 'LZNT1';
    comp_name[2] = 'LZ77';
    comp_name[3] = 'LZ77+Huffman';
    comp_name[4] = 'Pattern_V1';

    pos = 8;
    for(i = 0; i < cnt && (pos + 2 <= dlen); i++, pos +=2)
    {
      id = get_word(blob:comp_capa, pos:pos); 

      if(id >= 0 && id <=4)
        supported[max_index(supported)] = comp_name[id];
      else
        supported[max_index(supported)] = id; 
    }
    spad_log(message:"Found the following compression algorithms:"+max_index(supported));
  }
  return supported;
}

if(agent()) exit(0,"This plugin is disabled on Nessus Agents.");

port = kb_smb_transport();

# the port scanner ran and determined the SMB transport port isn't open
if (!get_port_state(port))
{
  audit(AUDIT_PORT_CLOSED, port);
}

all_smb_dialects = mklist(
                      SMB_DIALECT_0202,  # SMB 2.0.2: Windows 2008 SMB2 version.
                      SMB_DIALECT_0210,  # SMB 2.1:   Windows 7 SMB2 version.
                      0x222,  # SMB2_22: Early Windows 8 SMB2 version.
                      0x224,  # SMB2_24: Windows 8 beta SMB2 version.
                      SMB_DIALECT_0300,  # SMB 3.0:   Windows 8 SMB3 version. (mostly the same as SMB2_24)
                      SMB_DIALECT_0302,  # SMB 3.0.2: Windows 8.1 SMB3 version.
                      0x310,  # SMB3_10: early Windows 10 technical preview SMB3 version.
                      SMB_DIALECT_0311   # SMB 3.1.1: Windows 10 technical preview SMB3 version (maybe final)
                    );

header =              "_version_  _introduced in windows version_";
all_smb_dialect_names = mklist(
                      "2.0.2      Windows 2008  ",  # SMB 2.0.2: Windows 2008 SMB2 version.
                      "2.1        Windows 7     ",  # SMB 2.1:   Windows 7 SMB2 version.
                      "2.2.2      Windows 8 Beta",  # SMB2_22: Early Windows 8 SMB2 version.
                      "2.2.4      Windows 8 Beta",  # SMB2_24: Windows 8 beta SMB2 version.
                      "3.0        Windows 8     ",  # SMB 3.0:   Windows 8 SMB3 version. (mostly the same as SMB2_24)
                      "3.0.2      Windows 8.1   ",  # SMB 3.0.2: Windows 8.1 SMB3 version.
                      "3.1        Windows 10    ",  # SMB3_10: early Windows 10 technical preview SMB3 version.
                      "3.1.1      Windows 10    "   # SMB 3.1.1: Windows 10 technical preview SMB3 version (maybe final)
                    );

valid = NULL;
invalid = NULL;
foreach idx (keys(all_smb_dialects))
{
  smb_dialect = all_smb_dialects[idx];
  smb_dialect_name = all_smb_dialect_names[idx];
  if (!smb_session_init()) audit(AUDIT_FN_FAIL, 'smb_session_init');
  smb3_available = FALSE;
  if (smb_dialect == 0x310 || smb_dialect == SMB_DIALECT_0311)
  {
    smb3_available = TRUE;
  }
  ret = smb2_negotiate_protocol(smb_dialects: mklist(smb_dialect), smb3_available: smb3_available);
  dialect_chosen = ret[2];
  if (!isnull(ret) && dialect_chosen == smb_dialect)
  {
    valid += '\t'+smb_dialect_name+'\n';
    match_res = pregmatch(string:smb_dialect_name, pattern:"^(\d(\.\d)+)");
    # storing SMB dialect in the KB
    if (!isnull(match_res) && !isnull(match_res[1]))
    {
      replace_kb_item(name:"SMB/smb_dialect/"+match_res[1], value:TRUE);

      comp_capa = ret[21];
      
      comp_algs = smb_compression_algorithm(comp_capa:comp_capa);
      if (!empty_or_null(comp_algs))
      {
        spad_log(message:"Compression algorithms found for "+smb_dialect_name+": "+max_index(comp_algs));
        replace_kb_item(name:"SMB/smb_dialect/"+match_res[1]+"/compression", value:TRUE);
        foreach alg (comp_algs)
        {
          replace_kb_item(name:"SMB/smb_dialect/"+match_res[1]+"/compression/"+string(alg), value:TRUE);
        }
      }
      else
      {
        spad_log(message:"No compression algorithms found for "+smb_dialect_name);
      }
      
    }
    
  }
  else
  {
    invalid += '\t'+smb_dialect_name+'\n';
  }
  NetUseDel();
}

report = NULL;
if ( !isnull(valid) )
{
  report += '\nThe remote host supports the following SMB dialects :\n' + '\t' + header + '\n' + valid;
}

if ( !isnull(invalid) )
{
  report += '\nThe remote host does NOT support the following SMB dialects :\n' + '\t' + header + '\n' + invalid;

}
if ( !isnull(report) )
{
  security_report_v4(port:port, severity:SECURITY_NOTE, extra:report);
}
else audit(AUDIT_NOT_DETECT, 'SMB');
