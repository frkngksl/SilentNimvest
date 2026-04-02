import winim
import std/strutils

proc PrintBanner*():void = 
    var banner = """
 __ _ _            _       __ _                         _   
/ _(_) | ___ _ __ | |_  /\ \ (_)_ __ _____   _____  ___| |_ 
\ \| | |/ _ \ '_ \| __|/  \/ / | '_ ` _ \ \ / / _ \/ __| __|
_\ \ | |  __/ | | | |_/ /\  /| | | | | | \ V /  __/\__ \ |_ 
\__/_|_|\___|_| |_|\__\_\ \/ |_|_| |_| |_|\_/ \___||___/\__|
                                                                 
                         @R0h1rr1m                                       
"""
    echo banner

proc SeqToUnicode*(input:seq[byte]):string = 
  var index:int= 0
  var returnValue = newWString(0)
  var returnValueStr = ""
  while index <  input.len:
    returnValue.add(cast[WCHAR](input[index]))
    index=index+2
  returnValueStr = $returnValue
  return returnValueStr


proc hexStringToByteArray*(s: string): seq[byte] =
  var i = 0
  result = newSeq[byte](0)
  while i < s.len:
    result.add(parseHexInt(s[i .. i+1]).byte)
    i += 2
  return result
