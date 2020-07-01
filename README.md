# PEHeaderViewer
A PHP script that dumps the PE Header of an Windows executable file

## Information obtained:

#### COFF File Header
- Machine 
- Signature 
- NumberOfSections 
- TimeDateStamp 
- SizeOfOptionalHeader 
- Characteristics 

#### Optional Header
- SizeOfCode 
- SizeOfInitializedData
- SizeOfUninitializedData
- AddressOfEntryPoint 
- BaseOfCode 
- BaseOfData 
- ImageBase 
- ImportDirectoryRVA 
- ImportDirectorySize 
- ResourceDirectoryRVA 
- ResourceDirectorySize 
- IATDirectoryRVA 
- IATDirectorySize 

#### Section of IAT

#### Imported dlls

#### List of all sections
- Virtual Size
- Virtual Address	
- RawSize	
- RawAddress	
- Characteristics

#### Content dump of each section (ASCII and HEX)

#### UPX Detection
