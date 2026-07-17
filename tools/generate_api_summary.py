#!/usr/bin/env python3
import json, sys
from pathlib import Path
if len(sys.argv) != 3:
    raise SystemExit("usage: generate_api_summary.py Full-API-Dump.json output.inc")
raw=json.loads(Path(sys.argv[1]).read_text())
source_classes=raw.get("Classes",raw.get("classes",[]))
source_enums=raw.get("Enums",raw.get("enums",[]))
classes=[]
for cls in source_classes:
    if "name" in cls and "Name" not in cls:
        cls=dict(cls)
        cls["Name"]=cls.get("name")
        cls["Superclass"]=cls.get("baseClass") or ""
        cls["Tags"]=[] if cls.get("isScriptCreatable",True) else ["NotCreatable"]
        members=[]
        for member in cls.get("members",[]):
            converted=dict(member)
            converted["Name"]=member.get("name")
            converted["MemberType"]=member.get("memberType")
            if member.get("memberType")=="Property":
                converted["Security"]={"Read":member.get("readSecurity","None"),"Write":member.get("writeSecurity","None")}
                converted["ValueType"]={"Name":member.get("type",{}).get("type","")}
            else:
                converted["Security"]=member.get("security","None")
            members.append(converted)
        cls["Members"]=members
    normalized=dict(cls)
    normalized["Name"]=cls.get("Name")
    normalized["Superclass"]=cls.get("Superclass") or ""
    normalized["Tags"]=cls.get("Tags",[])
    normalized["Members"]=[dict(member) for member in cls.get("Members",[]) if member.get("Name") and member.get("MemberType")]
    classes.append(normalized)
enums=[]
for enum in source_enums:
    if "name" in enum and "Name" not in enum:
        enum=dict(enum)
        enum["Name"]=enum.get("name")
        enum["Items"]=[{"Name":name,"Value":value} for name,value in enum.get("items",{}).items()]
    normalized=dict(enum)
    normalized["Name"]=enum.get("Name")
    normalized["Items"]=[dict(item) for item in enum.get("Items",[]) if item.get("Name")]
    enums.append(normalized)
text=json.dumps({"Version":raw.get("Version",raw.get("version","")),"Classes":classes,"Enums":enums},separators=(",",":"))
Path(sys.argv[2]).parent.mkdir(parents=True, exist_ok=True)
chunks=[text[i:i+32000] for i in range(0,len(text),32000)]
out=["// Generated from the Roblox Studio Full API export.\n","#include <stddef.h>\n","static const char* kApiDumpSummaryJsonParts[] = {\n"]
for chunk in chunks:
    out.append("R\"APIJSON(" + chunk + ")APIJSON\",\n")
out.append("};\nstatic const size_t kApiDumpSummaryJsonPartCount = sizeof(kApiDumpSummaryJsonParts) / sizeof(kApiDumpSummaryJsonParts[0]);\n")
Path(sys.argv[2]).write_text("".join(out))
