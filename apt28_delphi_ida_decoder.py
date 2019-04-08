# @VK_Intel
# APT28 Delphi Zebrocy Decoder IDA Script
# Sample SHA256: 3a76c161401979a1899b6dfefb5e9fc67b62cad61b9998610442c80cdcf4bcb7
# function -> 0x0049A15C

def find_function_arg(addr):
  while True:
    addr = idc.PrevHead(addr)
    if GetMnem(addr) == "mov" and "eax" in GetOpnd(addr, 0):
      return GetOperandValue(addr, 1)
  return ""

def get_string(addr):
  out = ""
  while True:
    if Byte(addr) != 0:
      out += chr(Byte(addr))
    else:
      break
    addr += 1
  return out

def decode_xor(data):
  return data.decode("hex")

print "[*] Attempting to decode strings in APT28 Zebrocy Implant"
for x in XrefsTo(0x0049A15C, flags=0):
    ref =     find_function_arg(x.frm)
    string = get_string(ref)
    try:
     dec = decode_xor(string)
     print "Ref Addr: 0x%x | Decoded: %s" % (x.frm, dec)
     MakeComm(x.frm, dec)
     MakeComm(ref, dec)
    except:
     pass
